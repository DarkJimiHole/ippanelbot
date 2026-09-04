#!/usr/bin/env python3
from __future__ import annotations

import http.cookiejar
import argparse
import calendar
import getpass
import hmac
import html
import ipaddress
import json
import logging
import os
import re
import secrets
import signal
import sqlite3
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Callable
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


APP_VERSION = "0.2.0"
PAGE_SIZE = 3
PANEL_TRANSIENT_HTTP_STATUS = {502, 503, 504}
PANEL_TRANSIENT_RETRY_DELAYS = (5, 15)
API_INTERFACE = "api"
LEGACY_INTERFACE = "line"
API_TARGET_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
API_CONFIRM_BACKOFF_SECONDS = (5, 10, 15, 30)
V2_JOB_POLL_SECONDS = 2
V2_JOB_TIMEOUT_SECONDS = 300


class ConfigError(Exception):
    pass


class IppanelError(Exception):
    pass


class IppanelAuthExpired(IppanelError):
    pass


class IppanelTransientError(IppanelError):
    pass


class IppanelRateLimited(IppanelError):
    def __init__(self, path: str, retry_after: int | None = None):
        self.path = path
        self.retry_after = retry_after
        if retry_after and retry_after > 0:
            message = f"面板请求太频繁，请等待约 {retry_after} 秒后再试。"
        else:
            message = "面板请求太频繁，请稍等一会儿再试。"
        super().__init__(message)


class TelegramError(Exception):
    pass


class TelegramNetworkError(TelegramError):
    pass


class TelegramApiError(TelegramError):
    pass


class DdnsError(Exception):
    pass


class RelaySyncError(Exception):
    pass


@dataclass(frozen=True)
class Config:
    telegram_bot_token: str
    allowed_chat_ids: set[int]
    ippanel_mode: str
    ippanel_base_url: str
    ippanel_account: str
    ippanel_password: str
    ippanel_api_targets_file: Path
    ippanel_api_targets: tuple["ApiTarget", ...]
    api_change_initial_delay_seconds: int
    api_change_poll_interval_seconds: int
    api_change_confirm_timeout_seconds: int
    db_path: Path
    post_change_query_delay_seconds: int
    query_cache_seconds: int
    change_max_attempts: int
    change_retry_delay_seconds: int
    timezone_name: str
    poll_timeout_seconds: int
    panel_image_path: Path
    log_level: str
    ddns_enabled: bool
    cloudflare_api_token: str
    cloudflare_zone_id: str
    ddns_ttl_seconds: int
    ddns_sync_after_change: bool
    relay_sync_enabled: bool
    relay_sync_after_change: bool


@dataclass
class HttpResponse:
    status: int
    final_url: str
    content_type: str
    headers: dict[str, str]
    text: str


@dataclass(frozen=True)
class ApiTarget:
    target_id: str
    label: str
    token: str


@dataclass
class ZoneItem:
    router_id: str
    interface: str
    label: str
    dedicated_ip: str
    current_ip: str
    status: str
    status_msg: str

    @property
    def operable(self) -> bool:
        return self.status == "ok"

    @property
    def display_name(self) -> str:
        return self.label or self.dedicated_ip or self.current_ip or "目标机器"


@dataclass
class ScheduledChange:
    id: int
    chat_id: int
    router_id: str
    interface: str
    target_name: str
    run_at: int
    created_at: int
    status: str
    schedule_type: str = "once"
    interval_days: int = 0
    weekday: int = 0
    month_day: int = 0
    time_of_day: str = ""
    timezone_name: str = ""
    retry_count: int = 0


@dataclass
class DdnsBinding:
    id: int
    chat_id: int
    router_id: str
    interface: str
    target_name: str
    hostname: str
    record_id: str
    ttl: int
    proxied: bool
    last_ip: str
    last_update_at: int
    enabled: bool


@dataclass
class RelayBinding:
    id: int
    router_id: str
    interface: str
    internal_ip: str
    target_name: str
    receiver_url: str
    reporter: str
    secret: str
    receiver_target_name: str
    match_mode: str
    last_ip: str
    last_sync_at: int
    last_error: str
    enabled: bool


@dataclass
class ChangeContext:
    zone_before: ZoneItem | None
    reconnect_data: dict[str, Any]
    payload_after: dict[str, Any] | None
    zone_after: ZoneItem | None


@dataclass
class ApiChangeOperation:
    id: int
    chat_id: int
    message_id: int
    router_id: str
    interface: str
    target_name: str
    old_ip: str
    new_ip: str
    requested_at: int
    next_check_at: int
    confirm_deadline: int
    check_count: int
    api_uses_left: int | None
    next_allowed_at: int | None
    status: str
    last_error: str
    scheduled_job_id: int | None


def load_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        values[key] = value
    return values


def load_api_targets(path: Path) -> tuple[ApiTarget, ...]:
    if not path.exists():
        raise ConfigError(f"API targets file not found: {path}")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"Could not read API targets file {path}: {exc}") from exc

    if isinstance(raw, dict):
        raw = raw.get("targets")
    if not isinstance(raw, list) or not raw:
        raise ConfigError("API targets file must contain a non-empty JSON array.")

    targets: list[ApiTarget] = []
    seen_ids: set[str] = set()
    for index, item in enumerate(raw, start=1):
        if not isinstance(item, dict):
            raise ConfigError(f"API target #{index} must be a JSON object.")
        target_id = str(item.get("id") or "").strip()
        label = str(item.get("name") or item.get("label") or target_id).strip()
        token = str(item.get("token") or "").strip()
        if not API_TARGET_ID_PATTERN.fullmatch(target_id):
            raise ConfigError(
                f"API target #{index} id must be 1-32 characters using letters, numbers, _ or -."
            )
        if target_id in seen_ids:
            raise ConfigError(f"Duplicate API target id: {target_id}")
        if not label:
            raise ConfigError(f"API target '{target_id}' name must not be empty.")
        if not token:
            raise ConfigError(f"API target '{target_id}' token must not be empty.")
        seen_ids.add(target_id)
        targets.append(ApiTarget(target_id=target_id, label=label, token=token))
    return tuple(targets)


def read_config() -> Config:
    env_file = Path(os.environ.get("BOT_ENV_FILE", ".env"))
    env_values = load_env_file(env_file)

    def get(key: str, default: str = "") -> str:
        return os.environ.get(key, env_values.get(key, default)).strip()

    token = get("TELEGRAM_BOT_TOKEN")
    if not token:
        raise ConfigError("TELEGRAM_BOT_TOKEN is required.")

    allowed_chat_ids = parse_chat_ids(get("TELEGRAM_ALLOWED_CHAT_IDS"))

    panel_mode = get("IPPANEL_MODE", "legacy").lower()
    if panel_mode not in {"legacy", "api"}:
        raise ConfigError("IPPANEL_MODE must be legacy or api.")
    base_url = get("IPPANEL_BASE_URL", "https://ippanel.boil.network").rstrip("/")
    account = get("IPPANEL_ACCOUNT")
    password = get("IPPANEL_PASSWORD")
    if panel_mode == "legacy" and (not account or not password):
        raise ConfigError("IPPANEL_ACCOUNT and IPPANEL_PASSWORD are required in legacy mode.")

    api_targets_file = Path(
        get("IPPANEL_API_TARGETS_FILE", "ippanel-api-targets.json")
    ).expanduser()
    if not api_targets_file.is_absolute():
        api_targets_file = env_file.parent / api_targets_file
    if panel_mode == "api":
        api_targets = load_api_targets(api_targets_file)
    elif api_targets_file.exists():
        try:
            api_targets = load_api_targets(api_targets_file)
        except ConfigError:
            api_targets = ()
    else:
        api_targets = ()
    api_initial_delay = parse_int(get("API_CHANGE_INITIAL_DELAY_SECONDS", "5"), 5)
    api_poll_interval = parse_int(get("API_CHANGE_POLL_INTERVAL_SECONDS", "30"), 30)
    api_confirm_timeout = parse_int(get("API_CHANGE_CONFIRM_TIMEOUT_SECONDS", "300"), 300)

    db_path = Path(get("DB_PATH", "ippanel_bot.sqlite3")).expanduser()
    delay = parse_int(get("POST_CHANGE_QUERY_DELAY_SECONDS", "5"), default=5)
    query_cache_seconds = parse_int(get("QUERY_CACHE_SECONDS", "60"), default=60)
    change_max_attempts = parse_int(get("CHANGE_MAX_ATTEMPTS", "5"), default=5)
    change_retry_delay = parse_int(get("CHANGE_RETRY_DELAY_SECONDS", "60"), default=60)
    timezone_name = get("TIMEZONE", "Asia/Shanghai")
    poll_timeout = parse_int(get("POLL_TIMEOUT_SECONDS", "5"), default=5)
    panel_image_path = Path(get("PANEL_IMAGE_PATH", "pic.png")).expanduser()
    log_level = get("LOG_LEVEL", "INFO").upper()
    ddns_enabled = parse_bool(get("DDNS_ENABLED", "0"))
    cloudflare_api_token = get("CLOUDFLARE_API_TOKEN")
    cloudflare_zone_id = get("CLOUDFLARE_ZONE_ID")
    ddns_ttl_seconds = parse_int(get("DDNS_TTL_SECONDS", "60"), default=60)
    ddns_sync_after_change = parse_bool(get("DDNS_SYNC_AFTER_CHANGE", "1"), True)
    relay_sync_enabled = parse_bool(get("RELAY_SYNC_ENABLED", "0"))
    relay_sync_after_change = parse_bool(get("RELAY_SYNC_AFTER_CHANGE", "1"), True)

    return Config(
        telegram_bot_token=token,
        allowed_chat_ids=allowed_chat_ids,
        ippanel_mode=panel_mode,
        ippanel_base_url=base_url,
        ippanel_account=account,
        ippanel_password=password,
        ippanel_api_targets_file=api_targets_file,
        ippanel_api_targets=api_targets,
        api_change_initial_delay_seconds=max(1, min(300, api_initial_delay)),
        api_change_poll_interval_seconds=max(5, min(300, api_poll_interval)),
        api_change_confirm_timeout_seconds=max(30, min(3600, api_confirm_timeout)),
        db_path=db_path,
        post_change_query_delay_seconds=max(0, delay),
        query_cache_seconds=max(0, query_cache_seconds),
        change_max_attempts=max(1, min(10, change_max_attempts)),
        change_retry_delay_seconds=max(1, change_retry_delay),
        timezone_name=timezone_name,
        poll_timeout_seconds=max(1, min(50, poll_timeout)),
        panel_image_path=panel_image_path,
        log_level=log_level,
        ddns_enabled=ddns_enabled,
        cloudflare_api_token=cloudflare_api_token,
        cloudflare_zone_id=cloudflare_zone_id,
        ddns_ttl_seconds=normalize_cloudflare_ttl(ddns_ttl_seconds),
        ddns_sync_after_change=ddns_sync_after_change,
        relay_sync_enabled=relay_sync_enabled,
        relay_sync_after_change=relay_sync_after_change,
    )


def parse_chat_ids(raw: str) -> set[int]:
    chat_ids: set[int] = set()
    for item in raw.replace(";", ",").split(","):
        item = item.strip()
        if not item:
            continue
        try:
            chat_ids.add(int(item))
        except ValueError as exc:
            raise ConfigError(f"Invalid TELEGRAM_ALLOWED_CHAT_IDS item: {item}") from exc
    return chat_ids


def parse_int(raw: Any, default: int = 0) -> int:
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default


def optional_int(raw: Any) -> int | None:
    if raw is None or raw == "":
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def parse_bool(raw: Any, default: bool = False) -> bool:
    if raw is None:
        return default
    value = str(raw).strip().lower()
    if not value:
        return default
    return value in ("1", "true", "yes", "y", "on", "enable", "enabled")


def normalize_relay_match_mode(value: str) -> str:
    mode = str(value or "remark").strip().lower()
    if mode not in {"remark", "old_ip", "old_ip_unique"}:
        raise ValueError("match_mode must be remark, old_ip, or old_ip_unique")
    return mode


def validate_relay_url(value: str) -> str:
    url = str(value or "").strip()
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("receiver 地址必须是 http:// 或 https:// 开头的完整 URL。")
    return url


def relay_host_label(receiver_url: str) -> str:
    parsed = urllib.parse.urlparse(receiver_url)
    return parsed.hostname or parsed.netloc or receiver_url


def relay_match_mode_label(value: str) -> str:
    mode = normalize_relay_match_mode(value)
    labels = {
        "remark": "remark（按目标备注）",
        "old_ip": "old_ip（按旧目标 IP）",
        "old_ip_unique": "old_ip_unique（按唯一旧目标 IP）",
    }
    return labels[mode]


def relay_binding_matches_zone(binding: RelayBinding, zone: ZoneItem) -> bool:
    if binding.router_id != zone.router_id or binding.interface != zone.interface:
        return False
    if zone.dedicated_ip:
        return binding.internal_ip == zone.dedicated_ip
    return not binding.internal_ip


def normalize_cloudflare_ttl(raw: int) -> int:
    if raw == 1:
        return 1
    return max(60, min(86400, int(raw or 60)))


def load_timezone(name: str):
    name = (name or "Asia/Shanghai").strip()
    try:
        return ZoneInfo(name)
    except ZoneInfoNotFoundError as exc:
        normalized = name.upper().replace(" ", "")
        if normalized in ("UTC", "Z"):
            return timezone.utc
        if normalized in ("UTC+8", "GMT+8", "ASIA/SHANGHAI"):
            return timezone(timedelta(hours=8), "Asia/Shanghai")
        raise ConfigError(
            f"Unknown TIMEZONE '{name}'. Use an IANA name such as Asia/Shanghai."
        ) from exc


def format_run_time(timestamp: int, tz, timezone_name: str) -> str:
    run_at = datetime.fromtimestamp(timestamp, tz)
    return f"{run_at:%Y-%m-%d %H:%M:%S} {timezone_name}"


def parse_run_at(text: str, now: datetime) -> datetime:
    value = " ".join((text or "").strip().split())
    if not value:
        raise ValueError("empty time")

    if len(value) == 5 and value[2] == ":":
        hour = parse_int(value[:2], -1)
        minute = parse_int(value[3:], -1)
        if not (0 <= hour <= 23 and 0 <= minute <= 59):
            raise ValueError("bad HH:MM")
        candidate = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
        if candidate <= now:
            candidate += timedelta(days=1)
        return candidate

    normalized = value.replace("T", " ")
    for fmt in ("%Y-%m-%d %H:%M", "%Y/%m/%d %H:%M"):
        try:
            candidate = datetime.strptime(normalized, fmt)
            return candidate.replace(tzinfo=now.tzinfo)
        except ValueError:
            continue
    raise ValueError("bad scheduled time")


def parse_time_of_day(text: str) -> tuple[str, int, int]:
    value = (text or "").strip()
    if len(value) != 5 or value[2] != ":":
        raise ValueError("bad HH:MM")
    hour = parse_int(value[:2], -1)
    minute = parse_int(value[3:], -1)
    if not (0 <= hour <= 23 and 0 <= minute <= 59):
        raise ValueError("bad HH:MM")
    return f"{hour:02d}:{minute:02d}", hour, minute


def parse_custom_datetime(text: str, now: datetime) -> datetime:
    value = " ".join((text or "").strip().split()).replace("T", " ")
    for fmt in ("%Y-%m-%d %H:%M", "%Y/%m/%d %H:%M"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=now.tzinfo)
        except ValueError:
            continue
    raise ValueError("bad custom datetime")


def clamp_month_day(year: int, month: int, day: int) -> int:
    last_day = calendar.monthrange(year, month)[1]
    return min(max(1, day), last_day)


def add_months(year: int, month: int, months: int) -> tuple[int, int]:
    month_index = month - 1 + months
    return year + month_index // 12, month_index % 12 + 1


def first_every_days_run_at(now: datetime, interval_days: int, time_of_day: str) -> int:
    _, hour, minute = parse_time_of_day(time_of_day)
    interval_days = max(1, interval_days)
    candidate = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if candidate <= now:
        candidate += timedelta(days=interval_days)
    return int(candidate.timestamp())


def first_weekly_run_at(now: datetime, weekday: int, time_of_day: str) -> int:
    _, hour, minute = parse_time_of_day(time_of_day)
    if not (1 <= weekday <= 7):
        raise ValueError("weekday must be 1-7")
    days_ahead = (weekday - 1 - now.weekday()) % 7
    candidate = (now + timedelta(days=days_ahead)).replace(
        hour=hour, minute=minute, second=0, microsecond=0
    )
    if candidate <= now:
        candidate += timedelta(days=7)
    return int(candidate.timestamp())


def first_monthly_run_at(now: datetime, month_day: int, time_of_day: str) -> int:
    _, hour, minute = parse_time_of_day(time_of_day)
    if not (1 <= month_day <= 31):
        raise ValueError("month day must be 1-31")
    day = clamp_month_day(now.year, now.month, month_day)
    candidate = now.replace(day=day, hour=hour, minute=minute, second=0, microsecond=0)
    if candidate <= now:
        year, month = add_months(now.year, now.month, 1)
        day = clamp_month_day(year, month, month_day)
        candidate = now.replace(
            year=year, month=month, day=day, hour=hour, minute=minute, second=0, microsecond=0
        )
    return int(candidate.timestamp())


def is_recurring_schedule(schedule_type: str) -> bool:
    return schedule_type in {"every_days", "weekly", "monthly"}


def next_recurring_run_at(job: ScheduledChange, after_timestamp: int) -> int | None:
    if not is_recurring_schedule(job.schedule_type):
        return None
    tz = load_timezone(job.timezone_name or "Asia/Shanghai")
    after = datetime.fromtimestamp(after_timestamp, tz)
    previous = datetime.fromtimestamp(job.run_at, tz)
    _, hour, minute = parse_time_of_day(job.time_of_day or f"{previous:%H:%M}")

    if job.schedule_type == "every_days":
        interval = max(1, job.interval_days)
        candidate = previous + timedelta(days=interval)
        candidate = candidate.replace(hour=hour, minute=minute, second=0, microsecond=0)
        while candidate <= after:
            candidate += timedelta(days=interval)
        return int(candidate.timestamp())

    if job.schedule_type == "weekly":
        candidate = previous + timedelta(days=7)
        candidate = candidate.replace(hour=hour, minute=minute, second=0, microsecond=0)
        while candidate <= after:
            candidate += timedelta(days=7)
        return int(candidate.timestamp())

    if job.schedule_type == "monthly":
        year, month = previous.year, previous.month
        month_day = job.month_day or previous.day
        while True:
            year, month = add_months(year, month, 1)
            day = clamp_month_day(year, month, month_day)
            candidate = previous.replace(
                year=year,
                month=month,
                day=day,
                hour=hour,
                minute=minute,
                second=0,
                microsecond=0,
            )
            if candidate > after:
                return int(candidate.timestamp())
    return None


WEEKDAY_NAMES = {
    1: "周一",
    2: "周二",
    3: "周三",
    4: "周四",
    5: "周五",
    6: "周六",
    7: "周日",
}


BUTTON_COMMANDS = {
    "查询 IP": "/ip",
    "更换 IP": "/change",
    "任务列表": "/jobs",
    "DDNS": "/ddns",
    "帮助": "/help",
}


def panel_keyboard(ddns_enabled: bool = False) -> dict[str, Any]:
    return panel_inline_keyboard(ddns_enabled)


def panel_inline_keyboard(ddns_enabled: bool = False) -> dict[str, Any]:
    rows = [
        [
            {"text": "查询 IP", "callback_data": callback_data("cmd_ip", "", "")},
            {"text": "更换 IP", "callback_data": callback_data("cmd_change", "", "")},
        ]
    ]
    if ddns_enabled:
        rows.append(
            [
                {"text": "任务列表", "callback_data": callback_data("cmd_jobs", "", "")},
                {"text": "DDNS", "callback_data": callback_data("cmd_ddns", "", "")},
            ]
        )
        rows.append([{"text": "帮助", "callback_data": callback_data("cmd_help", "", "")}])
    else:
        rows.append(
            [
                {"text": "任务列表", "callback_data": callback_data("cmd_jobs", "", "")},
                {"text": "帮助", "callback_data": callback_data("cmd_help", "", "")},
            ]
        )
    return {
        "inline_keyboard": rows
    }


def total_pages(total_items: int, page_size: int = PAGE_SIZE) -> int:
    if total_items <= 0:
        return 1
    return max(1, (total_items + page_size - 1) // page_size)


def clamp_page(page: int, total_items: int, page_size: int = PAGE_SIZE) -> int:
    return max(0, min(page, total_pages(total_items, page_size) - 1))


def visible_page_numbers(current_page: int, pages: int, window: int = 5) -> list[int]:
    if pages <= window:
        return list(range(pages))
    start = max(0, min(current_page - window // 2, pages - window))
    return list(range(start, start + window))


def pagination_rows(action: str, page: int, total_items: int) -> list[list[dict[str, str]]]:
    pages = total_pages(total_items)
    if pages <= 1:
        return []

    prev_action = action if page > 0 else "noop"
    next_action = action if page < pages - 1 else "noop"
    rows = [
        [
            {"text": "上一页", "callback_data": callback_data(prev_action, max(0, page - 1), "")},
            {
                "text": "下一页",
                "callback_data": callback_data(next_action, min(pages - 1, page + 1), ""),
            },
        ]
    ]

    page_buttons = []
    for page_index in visible_page_numbers(page, pages):
        is_current = page_index == page
        page_buttons.append(
            {
                "text": f"[{page_index + 1}]" if is_current else str(page_index + 1),
                "callback_data": callback_data(
                    "noop" if is_current else action,
                    page_index,
                    "",
                ),
            }
        )
    rows.append(page_buttons)
    return rows


def validate_hostname(hostname: str) -> str:
    value = (hostname or "").strip().lower().rstrip(".")
    if not value or len(value) > 253:
        raise ValueError("hostname length")
    labels = value.split(".")
    if len(labels) < 2:
        raise ValueError("hostname needs a zone suffix")
    label_re = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
    if any(not label_re.match(label) for label in labels):
        raise ValueError("bad hostname label")
    return value


AUTO_LINK_RE = re.compile(
    r"(?<![\w/])((?:\d{1,3}\.){3}\d{1,3}|(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,})(?![\w/.])"
)
PURITY_LINK_RE = re.compile(r"www\.iplark\.com/((?:\d{1,3}\.){3}\d{1,3})")


def tg_bold(text: str) -> str:
    return str(text)


def purity_link_line(ip: str) -> str:
    return f"IP 纯净度：www.iplark.com/{ip}"


def apply_purity_links(text: str) -> str:
    def replace(match: re.Match[str]) -> str:
        display_url = match.group(0)
        href = f"https://{display_url}"
        return f'<a href="{href}">{display_url}</a>'

    return PURITY_LINK_RE.sub(replace, text)


def should_bold_html_line(line: str) -> bool:
    plain = re.sub(r"<[^>]+>", "", line).strip()
    if not plain:
        return False
    if line[:1].isspace():
        return False
    if re.match(r"^\d+\.\s+", plain):
        return True
    title_prefixes = (
        "当前 IP 状态",
        "中转同步绑定状态",
        "中转同步结果",
        "选择更换方式",
        "确认更换",
        "DDNS 管理",
        "DDNS 绑定列表",
        "DDNS 手动同步结果",
        "未执行任务",
        "计划任务",
    )
    if plain.startswith(title_prefixes):
        return True
    return any(
        marker in plain
        for marker in (
            "中转同步测试",
            "更换请求已完成",
            "换 IP 请求已受理",
            "换 IP 请求结果暂不明确",
            "换 IP 已完成",
            "换 IP 暂时无法确认",
            "更换失败",
            "多次尝试后 IP 仍未变化",
        )
    )


def apply_html_formatting(text: str) -> str:
    lines = text.split("\n")
    for index, line in enumerate(lines):
        if should_bold_html_line(line):
            lines[index] = f"<b>{line}</b>"
    return "\n".join(lines)


def telegram_html(text: str, code_autolinks: bool = True) -> str:
    text = str(text)
    if not code_autolinks:
        return apply_html_formatting(apply_purity_links(html.escape(text, quote=False)))
    parts: list[str] = []
    last = 0
    for match in AUTO_LINK_RE.finditer(text):
        parts.append(html.escape(text[last : match.start()], quote=False))
        parts.append(f"<code>{html.escape(match.group(1), quote=False)}</code>")
        last = match.end()
    parts.append(html.escape(text[last:], quote=False))
    return apply_html_formatting(apply_purity_links("".join(parts)))


def schedule_description(job: ScheduledChange) -> str:
    if job.schedule_type == "every_days":
        return f"每 {max(1, job.interval_days)} 天 {job.time_of_day}"
    if job.schedule_type == "weekly":
        return f"每周{WEEKDAY_NAMES.get(job.weekday, str(job.weekday))} {job.time_of_day}"
    if job.schedule_type == "monthly":
        return f"每月 {job.month_day} 日 {job.time_of_day}"
    return "一次性任务"


def safe_target_name(target_name: str, router_id: str = "", interface: str = "") -> str:
    value = (target_name or "").strip()
    if not value:
        return "目标机器"
    if interface == API_INTERFACE:
        return value
    if router_id and str(router_id) in value:
        return "目标机器"
    if interface and str(interface) in value:
        return "目标机器"
    return value


def short_text(text: str, limit: int = 64) -> str:
    text = " ".join((text or "").split())
    if len(text) <= limit:
        return text
    return text[: max(1, limit - 1)] + "…"


def telegram_photo_file_id(response: dict[str, Any]) -> str:
    result = response.get("result") if isinstance(response, dict) else {}
    photos = result.get("photo") if isinstance(result, dict) else []
    if not isinstance(photos, list) or not photos:
        return ""
    last = photos[-1]
    if not isinstance(last, dict):
        return ""
    return str(last.get("file_id") or "")


def get_key(mapping: Any, key: str) -> Any:
    if not isinstance(mapping, dict):
        return None
    if key in mapping:
        return mapping[key]
    key_str = str(key)
    if key_str in mapping:
        return mapping[key_str]
    try:
        key_int = int(key_str)
    except ValueError:
        return None
    return mapping.get(key_int)


def retry_after_seconds(headers: dict[str, str]) -> int | None:
    for key, value in headers.items():
        if key.lower() == "retry-after":
            seconds = parse_int(value, -1)
            return seconds if seconds >= 0 else None
    return None


def is_login_page(text: str) -> bool:
    lower = (text or "").lower()
    return (
        'action="/login"' in lower
        and 'name="account"' in lower
        and 'name="password"' in lower
    )


class BotStore:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        if self.db_path.parent:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scheduled_changes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id INTEGER NOT NULL,
                router_id TEXT NOT NULL,
                interface TEXT NOT NULL,
                target_name TEXT NOT NULL,
                run_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                finished_at INTEGER,
                last_error TEXT,
                schedule_type TEXT NOT NULL DEFAULT 'once',
                interval_days INTEGER NOT NULL DEFAULT 0,
                weekday INTEGER NOT NULL DEFAULT 0,
                month_day INTEGER NOT NULL DEFAULT 0,
                time_of_day TEXT NOT NULL DEFAULT '',
                timezone_name TEXT NOT NULL DEFAULT '',
                retry_count INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        self._ensure_columns(
            "scheduled_changes",
            {
                "schedule_type": "TEXT NOT NULL DEFAULT 'once'",
                "interval_days": "INTEGER NOT NULL DEFAULT 0",
                "weekday": "INTEGER NOT NULL DEFAULT 0",
                "month_day": "INTEGER NOT NULL DEFAULT 0",
                "time_of_day": "TEXT NOT NULL DEFAULT ''",
                "timezone_name": "TEXT NOT NULL DEFAULT ''",
                "retry_count": "INTEGER NOT NULL DEFAULT 0",
            },
        )
        self.conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_scheduled_changes_due
            ON scheduled_changes (status, run_at)
            """
        )
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ddns_bindings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id INTEGER NOT NULL,
                router_id TEXT NOT NULL,
                interface TEXT NOT NULL,
                target_name TEXT NOT NULL,
                hostname TEXT NOT NULL,
                record_id TEXT NOT NULL DEFAULT '',
                ttl INTEGER NOT NULL DEFAULT 1,
                proxied INTEGER NOT NULL DEFAULT 0,
                last_ip TEXT NOT NULL DEFAULT '',
                last_update_at INTEGER NOT NULL DEFAULT 0,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                UNIQUE(chat_id, router_id, interface)
            )
            """
        )
        self.conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_ddns_bindings_chat
            ON ddns_bindings (chat_id, enabled, id)
            """
        )
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS relay_bindings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                router_id TEXT NOT NULL,
                interface TEXT NOT NULL,
                internal_ip TEXT NOT NULL,
                target_name TEXT NOT NULL,
                receiver_url TEXT NOT NULL,
                reporter TEXT NOT NULL,
                secret TEXT NOT NULL,
                receiver_target_name TEXT NOT NULL,
                match_mode TEXT NOT NULL DEFAULT 'remark',
                last_ip TEXT NOT NULL DEFAULT '',
                last_sync_at INTEGER NOT NULL DEFAULT 0,
                last_error TEXT NOT NULL DEFAULT '',
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                UNIQUE(router_id, interface, internal_ip, receiver_url, receiver_target_name)
            )
            """
        )
        self.conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_relay_bindings_zone
            ON relay_bindings (router_id, interface, enabled, id)
            """
        )
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS api_change_operations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id INTEGER NOT NULL,
                message_id INTEGER NOT NULL DEFAULT 0,
                router_id TEXT NOT NULL,
                interface TEXT NOT NULL,
                target_name TEXT NOT NULL,
                old_ip TEXT NOT NULL,
                new_ip TEXT NOT NULL DEFAULT '',
                requested_at INTEGER NOT NULL,
                next_check_at INTEGER NOT NULL,
                confirm_deadline INTEGER NOT NULL,
                check_count INTEGER NOT NULL DEFAULT 0,
                api_uses_left INTEGER,
                next_allowed_at INTEGER,
                status TEXT NOT NULL DEFAULT 'confirming',
                last_error TEXT NOT NULL DEFAULT '',
                scheduled_job_id INTEGER,
                finished_at INTEGER
            )
            """
        )
        self.conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_api_change_operations_due
            ON api_change_operations (status, next_check_at)
            """
        )
        self.conn.execute("DROP INDEX IF EXISTS idx_api_change_operations_active_target")
        self.conn.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_api_change_operations_active_target
            ON api_change_operations (router_id, interface)
            WHERE status IN ('requesting', 'confirming')
            """
        )
        self.conn.commit()

    def _ensure_columns(self, table: str, columns: dict[str, str]) -> None:
        existing = {
            str(row["name"])
            for row in self.conn.execute(f"PRAGMA table_info({table})").fetchall()
        }
        for name, definition in columns.items():
            if name not in existing:
                self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")

    def add_scheduled_change(
        self,
        chat_id: int,
        router_id: str,
        interface: str,
        target_name: str,
        run_at: int,
        schedule_type: str = "once",
        interval_days: int = 0,
        weekday: int = 0,
        month_day: int = 0,
        time_of_day: str = "",
        timezone_name: str = "",
    ) -> int:
        now = int(time.time())
        cur = self.conn.execute(
            """
            INSERT INTO scheduled_changes
              (chat_id, router_id, interface, target_name, run_at, created_at, status,
               schedule_type, interval_days, weekday, month_day, time_of_day, timezone_name)
            VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?, ?)
            """,
            (
                int(chat_id),
                str(router_id),
                str(interface),
                target_name.strip() or "目标机器",
                int(run_at),
                now,
                schedule_type,
                int(interval_days),
                int(weekday),
                int(month_day),
                time_of_day,
                timezone_name,
            ),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def list_scheduled_changes(self, chat_id: int | None = None) -> list[ScheduledChange]:
        if chat_id is None:
            rows = self.conn.execute(
                """
                SELECT id, chat_id, router_id, interface, target_name, run_at, created_at, status,
                       schedule_type, interval_days, weekday, month_day, time_of_day, timezone_name,
                       retry_count
                FROM scheduled_changes
                WHERE status = 'pending'
                ORDER BY run_at, id
                """
            ).fetchall()
        else:
            rows = self.conn.execute(
                """
                SELECT id, chat_id, router_id, interface, target_name, run_at, created_at, status,
                       schedule_type, interval_days, weekday, month_day, time_of_day, timezone_name,
                       retry_count
                FROM scheduled_changes
                WHERE status = 'pending' AND chat_id = ?
                ORDER BY run_at, id
                """,
                (int(chat_id),),
            ).fetchall()
        return [self._scheduled_change_from_row(row) for row in rows]

    def due_scheduled_changes(self, now: int, limit: int = 5) -> list[ScheduledChange]:
        rows = self.conn.execute(
            """
            SELECT id, chat_id, router_id, interface, target_name, run_at, created_at, status,
                   schedule_type, interval_days, weekday, month_day, time_of_day, timezone_name,
                   retry_count
            FROM scheduled_changes
            WHERE status = 'pending' AND run_at <= ?
            ORDER BY run_at, id
            LIMIT ?
            """,
            (int(now), int(limit)),
        ).fetchall()
        return [self._scheduled_change_from_row(row) for row in rows]

    def get_scheduled_change(self, job_id: int) -> ScheduledChange | None:
        row = self.conn.execute(
            """
            SELECT id, chat_id, router_id, interface, target_name, run_at, created_at, status,
                   schedule_type, interval_days, weekday, month_day, time_of_day, timezone_name,
                   retry_count
            FROM scheduled_changes
            WHERE id = ?
            """,
            (int(job_id),),
        ).fetchone()
        return self._scheduled_change_from_row(row) if row else None

    def claim_scheduled_change(self, job_id: int) -> bool:
        cur = self.conn.execute(
            """
            UPDATE scheduled_changes
            SET status = 'running'
            WHERE id = ? AND status = 'pending'
            """,
            (int(job_id),),
        )
        self.conn.commit()
        return cur.rowcount == 1

    def finish_scheduled_change(self, job_id: int, status: str, error: str = "") -> None:
        self.conn.execute(
            """
            UPDATE scheduled_changes
            SET status = ?, finished_at = ?, last_error = ?
            WHERE id = ?
            """,
            (status, int(time.time()), error[:1000], int(job_id)),
        )
        self.conn.commit()

    def reschedule_scheduled_change(
        self, job_id: int, next_run_at: int, error: str = "", retry_count: int = 0
    ) -> None:
        self.conn.execute(
            """
            UPDATE scheduled_changes
            SET status = 'pending', run_at = ?, finished_at = ?, last_error = ?, retry_count = ?
            WHERE id = ?
            """,
            (int(next_run_at), int(time.time()), error[:1000], int(retry_count), int(job_id)),
        )
        self.conn.commit()

    def cancel_scheduled_change(self, job_id: int, chat_id: int) -> bool:
        cur = self.conn.execute(
            """
            UPDATE scheduled_changes
            SET status = 'canceled', finished_at = ?
            WHERE id = ? AND chat_id = ? AND status = 'pending'
            """,
            (int(time.time()), int(job_id), int(chat_id)),
        )
        self.conn.commit()
        return cur.rowcount == 1

    def upsert_ddns_binding(
        self,
        chat_id: int,
        router_id: str,
        interface: str,
        target_name: str,
        hostname: str,
        record_id: str = "",
        ttl: int = 1,
        proxied: bool = False,
        last_ip: str = "",
    ) -> int:
        now = int(time.time())
        existing = self.conn.execute(
            """
            SELECT id FROM ddns_bindings
            WHERE chat_id = ? AND router_id = ? AND interface = ?
            """,
            (int(chat_id), str(router_id), str(interface)),
        ).fetchone()
        if existing:
            binding_id = int(existing["id"])
            self.conn.execute(
                """
                UPDATE ddns_bindings
                SET target_name = ?, hostname = ?, record_id = ?, ttl = ?, proxied = ?,
                    last_ip = ?, enabled = 1, updated_at = ?
                WHERE id = ?
                """,
                (
                    target_name.strip() or "目标机器",
                    hostname,
                    record_id,
                    max(1, int(ttl or 1)),
                    1 if proxied else 0,
                    last_ip,
                    now,
                    binding_id,
                ),
            )
            self.conn.commit()
            return binding_id

        cur = self.conn.execute(
            """
            INSERT INTO ddns_bindings
              (chat_id, router_id, interface, target_name, hostname, record_id, ttl,
               proxied, last_ip, last_update_at, enabled, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 1, ?, ?)
            """,
            (
                int(chat_id),
                str(router_id),
                str(interface),
                target_name.strip() or "目标机器",
                hostname,
                record_id,
                max(1, int(ttl or 1)),
                1 if proxied else 0,
                last_ip,
                now,
                now,
            ),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def list_ddns_bindings(self, chat_id: int) -> list[DdnsBinding]:
        rows = self.conn.execute(
            """
            SELECT id, chat_id, router_id, interface, target_name, hostname, record_id,
                   ttl, proxied, last_ip, last_update_at, enabled
            FROM ddns_bindings
            WHERE chat_id = ? AND enabled = 1
            ORDER BY id
            """,
            (int(chat_id),),
        ).fetchall()
        return [self._ddns_binding_from_row(row) for row in rows]

    def get_ddns_binding(
        self, chat_id: int, router_id: str, interface: str
    ) -> DdnsBinding | None:
        row = self.conn.execute(
            """
            SELECT id, chat_id, router_id, interface, target_name, hostname, record_id,
                   ttl, proxied, last_ip, last_update_at, enabled
            FROM ddns_bindings
            WHERE chat_id = ? AND router_id = ? AND interface = ? AND enabled = 1
            """,
            (int(chat_id), str(router_id), str(interface)),
        ).fetchone()
        return self._ddns_binding_from_row(row) if row else None

    def get_ddns_binding_for_zone(
        self,
        chat_id: int,
        router_id: str,
        interface: str,
        target_name: str = "",
        previous_ip: str = "",
    ) -> DdnsBinding | None:
        binding = self.get_ddns_binding(chat_id, router_id, interface)
        if binding:
            return binding

        candidates = self.conn.execute(
            """
            SELECT id, chat_id, router_id, interface, target_name, hostname, record_id,
                   ttl, proxied, last_ip, last_update_at, enabled
            FROM ddns_bindings
            WHERE chat_id = ? AND enabled = 1
            ORDER BY id
            """,
            (int(chat_id),),
        ).fetchall()
        target_name = target_name.strip()
        previous_ip = previous_ip.strip()
        matches = []
        if target_name:
            matches = [
                row
                for row in candidates
                if str(row["target_name"] or "").strip() == target_name
            ]
        if len(matches) != 1 and previous_ip:
            ip_matches = [
                row
                for row in candidates
                if str(row["last_ip"] or "").strip() == previous_ip
            ]
            if len(ip_matches) == 1:
                matches = ip_matches
        if len(matches) != 1:
            return None

        row = matches[0]
        try:
            self.conn.execute(
                """
                UPDATE ddns_bindings
                SET router_id = ?, interface = ?, target_name = ?, updated_at = ?
                WHERE id = ? AND chat_id = ? AND enabled = 1
                """,
                (
                    str(router_id),
                    str(interface),
                    target_name or str(row["target_name"] or "目标机器"),
                    int(time.time()),
                    int(row["id"]),
                    int(chat_id),
                ),
            )
            self.conn.commit()
        except sqlite3.IntegrityError:
            self.conn.rollback()
            return None
        logging.info(
            "Migrated DDNS binding %s from %s/%s to %s/%s",
            row["id"],
            row["router_id"],
            row["interface"],
            router_id,
            interface,
        )
        return self.get_ddns_binding(chat_id, router_id, interface)

    def update_ddns_result(
        self, binding_id: int, record_id: str, ip: str, ttl: int = 1, proxied: bool = False
    ) -> None:
        now = int(time.time())
        self.conn.execute(
            """
            UPDATE ddns_bindings
            SET record_id = ?, last_ip = ?, ttl = ?, proxied = ?, last_update_at = ?, updated_at = ?
            WHERE id = ?
            """,
            (
                str(record_id),
                str(ip),
                max(1, int(ttl or 1)),
                1 if proxied else 0,
                now,
                now,
                int(binding_id),
            ),
        )
        self.conn.commit()

    def delete_ddns_binding(self, binding_id: int, chat_id: int) -> bool:
        cur = self.conn.execute(
            """
            UPDATE ddns_bindings
            SET enabled = 0, updated_at = ?
            WHERE id = ? AND chat_id = ? AND enabled = 1
            """,
            (int(time.time()), int(binding_id), int(chat_id)),
        )
        self.conn.commit()
        return cur.rowcount == 1

    def upsert_relay_binding(
        self,
        router_id: str,
        interface: str,
        internal_ip: str,
        target_name: str,
        receiver_url: str,
        reporter: str,
        secret: str,
        receiver_target_name: str,
        match_mode: str = "remark",
        last_ip: str = "",
    ) -> int:
        now = int(time.time())
        last_ip = str(last_ip or "").strip()
        existing = self.conn.execute(
            """
            SELECT id FROM relay_bindings
            WHERE router_id = ? AND interface = ? AND internal_ip = ?
              AND receiver_url = ? AND receiver_target_name = ?
            """,
            (
                str(router_id),
                str(interface),
                str(internal_ip),
                receiver_url,
                receiver_target_name,
            ),
        ).fetchone()
        if existing:
            binding_id = int(existing["id"])
            self.conn.execute(
                """
                UPDATE relay_bindings
                SET target_name = ?, reporter = ?, secret = ?, match_mode = ?,
                    last_ip = COALESCE(NULLIF(?, ''), last_ip),
                    enabled = 1, last_error = '', updated_at = ?
                WHERE id = ?
                """,
                (
                    target_name.strip() or "目标机器",
                    reporter,
                    secret,
                    normalize_relay_match_mode(match_mode),
                    last_ip,
                    now,
                    binding_id,
                ),
            )
            self.conn.commit()
            return binding_id

        cur = self.conn.execute(
            """
            INSERT INTO relay_bindings
              (router_id, interface, internal_ip, target_name, receiver_url, reporter, secret,
               receiver_target_name, match_mode, last_ip, enabled, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
            """,
            (
                str(router_id),
                str(interface),
                str(internal_ip),
                target_name.strip() or "目标机器",
                receiver_url,
                reporter,
                secret,
                receiver_target_name,
                normalize_relay_match_mode(match_mode),
                last_ip,
                now,
                now,
            ),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def list_relay_bindings(self) -> list[RelayBinding]:
        rows = self.conn.execute(
            """
            SELECT id, router_id, interface, internal_ip, target_name, receiver_url,
                   reporter, secret, receiver_target_name, match_mode, last_ip,
                   last_sync_at, last_error, enabled
            FROM relay_bindings
            WHERE enabled = 1
            ORDER BY id
            """
        ).fetchall()
        return [self._relay_binding_from_row(row) for row in rows]

    def list_relay_bindings_for_zone(
        self, router_id: str, interface: str
    ) -> list[RelayBinding]:
        rows = self.conn.execute(
            """
            SELECT id, router_id, interface, internal_ip, target_name, receiver_url,
                   reporter, secret, receiver_target_name, match_mode, last_ip,
                   last_sync_at, last_error, enabled
            FROM relay_bindings
            WHERE router_id = ? AND interface = ? AND enabled = 1
            ORDER BY id
            """,
            (str(router_id), str(interface)),
        ).fetchall()
        return [self._relay_binding_from_row(row) for row in rows]

    def migrate_relay_bindings_for_zone(
        self,
        router_id: str,
        interface: str,
        target_name: str,
        internal_ip: str = "",
        previous_ip: str = "",
    ) -> list[RelayBinding]:
        existing = self.list_relay_bindings_for_zone(router_id, interface)
        target_name = target_name.strip()
        internal_ip = internal_ip.strip()
        previous_ip = previous_ip.strip()
        if existing or not target_name:
            return existing

        rows = self.conn.execute(
            """
            SELECT id, router_id, interface, target_name, internal_ip, last_ip
            FROM relay_bindings
            WHERE enabled = 1
            ORDER BY id
            """
        ).fetchall()

        named_rows = [
            row for row in rows if str(row["target_name"] or "").strip() == target_name
        ]
        candidates = named_rows
        if previous_ip:
            ip_rows = [
                row for row in rows if str(row["last_ip"] or "").strip() == previous_ip
            ]
            ip_ids = {int(row["id"]) for row in ip_rows}
            named_ip_rows = [row for row in named_rows if int(row["id"]) in ip_ids]
            if named_ip_rows:
                candidates = named_ip_rows
            elif not candidates and ip_rows:
                if len({str(row["target_name"] or "").strip() for row in ip_rows}) == 1:
                    candidates = ip_rows
        if not candidates:
            return []

        if internal_ip:
            exact_rows = [
                row
                for row in candidates
                if str(row["internal_ip"] or "").strip() == internal_ip
            ]
            if exact_rows:
                candidates = exact_rows
            else:
                blank_rows = [
                    row for row in candidates if not str(row["internal_ip"] or "").strip()
                ]
                if not blank_rows or any(
                    str(row["internal_ip"] or "").strip() for row in candidates
                ):
                    return []
                candidates = blank_rows
        else:
            if len({str(row["internal_ip"] or "").strip() for row in candidates}) > 1:
                return []
        if not candidates:
            return []

        try:
            now = int(time.time())
            self.conn.executemany(
                """
                UPDATE relay_bindings
                SET router_id = ?, interface = ?, internal_ip = ?, target_name = ?, updated_at = ?
                WHERE id = ? AND enabled = 1
                """,
                [
                    (
                        str(router_id),
                        str(interface),
                        internal_ip,
                        target_name,
                        now,
                        int(row["id"]),
                    )
                    for row in candidates
                ],
            )
            self.conn.commit()
        except sqlite3.IntegrityError:
            self.conn.rollback()
            return []
        logging.info(
            "Migrated relay bindings %s to %s/%s",
            ",".join(str(row["id"]) for row in candidates),
            router_id,
            interface,
        )
        return self.list_relay_bindings_for_zone(router_id, interface)

    def get_relay_binding(self, binding_id: int) -> RelayBinding | None:
        row = self.conn.execute(
            """
            SELECT id, router_id, interface, internal_ip, target_name, receiver_url,
                   reporter, secret, receiver_target_name, match_mode, last_ip,
                   last_sync_at, last_error, enabled
            FROM relay_bindings
            WHERE id = ? AND enabled = 1
            """,
            (int(binding_id),),
        ).fetchone()
        return self._relay_binding_from_row(row) if row else None

    def update_relay_binding(
        self,
        binding_id: int,
        receiver_url: str,
        reporter: str,
        secret: str,
        receiver_target_name: str,
        match_mode: str,
    ) -> bool:
        now = int(time.time())
        cur = self.conn.execute(
            """
            UPDATE relay_bindings
            SET receiver_url = ?, reporter = ?, secret = ?, receiver_target_name = ?,
                match_mode = ?, last_error = '', updated_at = ?
            WHERE id = ? AND enabled = 1
            """,
            (
                receiver_url,
                reporter,
                secret,
                receiver_target_name,
                normalize_relay_match_mode(match_mode),
                now,
                int(binding_id),
            ),
        )
        self.conn.commit()
        return cur.rowcount == 1

    def delete_relay_binding(self, binding_id: int) -> bool:
        now = int(time.time())
        cur = self.conn.execute(
            """
            UPDATE relay_bindings
            SET enabled = 0, updated_at = ?
            WHERE id = ? AND enabled = 1
            """,
            (now, int(binding_id)),
        )
        self.conn.commit()
        return cur.rowcount == 1

    def update_relay_result(self, binding_id: int, ip: str, error: str = "") -> None:
        now = int(time.time())
        self.conn.execute(
            """
            UPDATE relay_bindings
            SET last_ip = ?, last_sync_at = ?, last_error = ?, updated_at = ?
            WHERE id = ?
            """,
            (str(ip), now, error[:1000], now, int(binding_id)),
        )
        self.conn.commit()

    def add_api_change_operation(
        self,
        chat_id: int,
        message_id: int,
        router_id: str,
        interface: str,
        target_name: str,
        old_ip: str,
        requested_at: int,
        next_check_at: int,
        confirm_deadline: int,
        scheduled_job_id: int | None = None,
    ) -> int:
        try:
            cur = self.conn.execute(
                """
                INSERT INTO api_change_operations
                  (chat_id, message_id, router_id, interface, target_name, old_ip,
                   requested_at, next_check_at, confirm_deadline, status, scheduled_job_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'requesting', ?)
                """,
                (
                    int(chat_id),
                    int(message_id),
                    str(router_id),
                    str(interface),
                    target_name.strip() or "目标机器",
                    old_ip,
                    int(requested_at),
                    int(next_check_at),
                    int(confirm_deadline),
                    scheduled_job_id,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise IppanelError("这台机器已有正在确认的新 IP，请勿重复提交。") from exc
        self.conn.commit()
        return int(cur.lastrowid)

    def active_api_change(self, router_id: str, interface: str) -> ApiChangeOperation | None:
        row = self.conn.execute(
            """
            SELECT * FROM api_change_operations
            WHERE router_id = ? AND interface = ?
              AND status IN ('requesting', 'confirming')
            ORDER BY id DESC LIMIT 1
            """,
            (str(router_id), str(interface)),
        ).fetchone()
        return self._api_change_operation_from_row(row) if row else None

    def latest_api_cooldown(self, router_id: str, interface: str) -> int | None:
        row = self.conn.execute(
            """
            SELECT next_allowed_at FROM api_change_operations
            WHERE router_id = ? AND interface = ? AND next_allowed_at IS NOT NULL
            ORDER BY id DESC LIMIT 1
            """,
            (str(router_id), str(interface)),
        ).fetchone()
        if not row or row["next_allowed_at"] is None:
            return None
        return int(row["next_allowed_at"])

    def due_api_changes(self, now: int, limit: int = 5) -> list[ApiChangeOperation]:
        rows = self.conn.execute(
            """
            SELECT * FROM api_change_operations
            WHERE status IN ('requesting', 'confirming') AND next_check_at <= ?
            ORDER BY next_check_at, id
            LIMIT ?
            """,
            (int(now), int(limit)),
        ).fetchall()
        return [self._api_change_operation_from_row(row) for row in rows]

    def accept_api_change_operation(
        self,
        operation_id: int,
        api_uses_left: int | None,
        next_allowed_at: int | None,
        error: str = "",
    ) -> None:
        self.conn.execute(
            """
            UPDATE api_change_operations
            SET status = 'confirming', api_uses_left = ?, next_allowed_at = ?, last_error = ?
            WHERE id = ? AND status = 'requesting'
            """,
            (api_uses_left, next_allowed_at, error[:1000], int(operation_id)),
        )
        self.conn.commit()

    def reschedule_api_change(
        self, operation_id: int, next_check_at: int, check_count: int, error: str = ""
    ) -> None:
        self.conn.execute(
            """
            UPDATE api_change_operations
            SET next_check_at = ?, check_count = ?, last_error = ?
            WHERE id = ? AND status IN ('requesting', 'confirming')
            """,
            (int(next_check_at), int(check_count), error[:1000], int(operation_id)),
        )
        self.conn.commit()

    def finish_api_change(
        self, operation_id: int, status: str, new_ip: str = "", error: str = ""
    ) -> None:
        self.conn.execute(
            """
            UPDATE api_change_operations
            SET status = ?, new_ip = ?, last_error = ?, finished_at = ?
            WHERE id = ? AND status IN ('requesting', 'confirming')
            """,
            (status, new_ip, error[:1000], int(time.time()), int(operation_id)),
        )
        self.conn.commit()

    def _scheduled_change_from_row(self, row: sqlite3.Row) -> ScheduledChange:
        return ScheduledChange(
            id=int(row["id"]),
            chat_id=int(row["chat_id"]),
            router_id=str(row["router_id"]),
            interface=str(row["interface"]),
            target_name=str(row["target_name"]),
            run_at=int(row["run_at"]),
            created_at=int(row["created_at"]),
            status=str(row["status"]),
            schedule_type=str(row["schedule_type"] or "once"),
            interval_days=int(row["interval_days"] or 0),
            weekday=int(row["weekday"] or 0),
            month_day=int(row["month_day"] or 0),
            time_of_day=str(row["time_of_day"] or ""),
            timezone_name=str(row["timezone_name"] or ""),
            retry_count=int(row["retry_count"] or 0),
        )

    def _ddns_binding_from_row(self, row: sqlite3.Row) -> DdnsBinding:
        return DdnsBinding(
            id=int(row["id"]),
            chat_id=int(row["chat_id"]),
            router_id=str(row["router_id"]),
            interface=str(row["interface"]),
            target_name=str(row["target_name"] or "目标机器"),
            hostname=str(row["hostname"] or ""),
            record_id=str(row["record_id"] or ""),
            ttl=parse_int(row["ttl"], 1),
            proxied=bool(parse_int(row["proxied"], 0)),
            last_ip=str(row["last_ip"] or ""),
            last_update_at=parse_int(row["last_update_at"], 0),
            enabled=bool(parse_int(row["enabled"], 1)),
        )

    def _relay_binding_from_row(self, row: sqlite3.Row) -> RelayBinding:
        return RelayBinding(
            id=int(row["id"]),
            router_id=str(row["router_id"]),
            interface=str(row["interface"]),
            internal_ip=str(row["internal_ip"] or ""),
            target_name=str(row["target_name"] or "目标机器"),
            receiver_url=str(row["receiver_url"] or ""),
            reporter=str(row["reporter"] or ""),
            secret=str(row["secret"] or ""),
            receiver_target_name=str(row["receiver_target_name"] or ""),
            match_mode=normalize_relay_match_mode(str(row["match_mode"] or "remark")),
            last_ip=str(row["last_ip"] or ""),
            last_sync_at=parse_int(row["last_sync_at"], 0),
            last_error=str(row["last_error"] or ""),
            enabled=bool(parse_int(row["enabled"], 1)),
        )

    def _api_change_operation_from_row(self, row: sqlite3.Row) -> ApiChangeOperation:
        return ApiChangeOperation(
            id=int(row["id"]),
            chat_id=int(row["chat_id"]),
            message_id=parse_int(row["message_id"], 0),
            router_id=str(row["router_id"]),
            interface=str(row["interface"]),
            target_name=str(row["target_name"] or "目标机器"),
            old_ip=str(row["old_ip"] or ""),
            new_ip=str(row["new_ip"] or ""),
            requested_at=int(row["requested_at"]),
            next_check_at=int(row["next_check_at"]),
            confirm_deadline=int(row["confirm_deadline"]),
            check_count=parse_int(row["check_count"], 0),
            api_uses_left=(
                int(row["api_uses_left"]) if row["api_uses_left"] is not None else None
            ),
            next_allowed_at=(
                int(row["next_allowed_at"]) if row["next_allowed_at"] is not None else None
            ),
            status=str(row["status"]),
            last_error=str(row["last_error"] or ""),
            scheduled_job_id=(
                int(row["scheduled_job_id"])
                if row["scheduled_job_id"] is not None
                else None
            ),
        )

    def close(self) -> None:
        self.conn.close()


class IppanelClient:
    def __init__(
        self, base_url: str, account: str, password: str, query_cache_seconds: int = 60
    ):
        self.mode = "legacy"
        self.base_url = base_url.rstrip("/")
        self.account = account
        self.password = password
        self.query_cache_seconds = max(0, query_cache_seconds)
        self.cookie_jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cookie_jar)
        )
        self.logged_in = False
        self.csrf_token = ""
        self._query_all_cache: dict[str, Any] | None = None
        self._query_all_cache_at = 0.0

    def login(self, force: bool = False) -> None:
        if self.logged_in and not force:
            return
        logging.info("Logging in to ippanel")
        response = self._request_raw(
            "/login",
            method="POST",
            form_data={"account": self.account, "password": self.password},
            timeout=30,
        )
        if response.status == 429:
            raise IppanelRateLimited("/login", retry_after_seconds(response.headers))
        if response.status in PANEL_TRANSIENT_HTTP_STATUS:
            raise IppanelTransientError(f"Panel login failed with HTTP {response.status}.")
        if response.status >= 400:
            raise IppanelError(f"Panel login failed with HTTP {response.status}.")
        if is_login_page(response.text) and response.final_url.rstrip("/").endswith("/login"):
            raise IppanelError("Panel login failed. Check IPPANEL_ACCOUNT and IPPANEL_PASSWORD.")
        self.logged_in = True
        self.csrf_token = ""

    def query_all(self, force: bool = False) -> dict[str, Any]:
        now = time.monotonic()
        if (
            not force
            and self._query_all_cache is not None
            and self.query_cache_seconds > 0
            and now - self._query_all_cache_at <= self.query_cache_seconds
        ):
            return dict(self._query_all_cache)

        try:
            lines_payload = self._request_json_authed(
                "/api/v2/lines", method="GET", timeout=60
            )
        except IppanelRateLimited:
            if self._query_all_cache is not None:
                logging.info("Using cached query_all payload after panel rate limit")
                return dict(self._query_all_cache)
            raise

        payload = self._normalize_lines_payload(lines_payload)
        self._query_all_cache = dict(payload)
        self._query_all_cache_at = now
        return payload

    def reconnect(self, router_id: str, interface: str) -> dict[str, Any]:
        self._query_all_cache = None
        self._query_all_cache_at = 0.0
        if str(interface) != LEGACY_INTERFACE:
            raise IppanelError("新版面板线路标识无效，请重新打开机器列表。")

        old_ip = self.get_target_ip(router_id, interface)
        start_payload = self._request_json_authed(
            f"/api/v2/lines/{urllib.parse.quote(str(router_id), safe='')}/reconnect/async",
            method="POST",
            json_data={},
            timeout=30,
            csrf=True,
        )

        if start_payload.get("error"):
            return dict(start_payload)

        job_id = str(start_payload.get("job_id") or "").strip()
        if not job_id:
            return self._normalize_v2_change_result(start_payload, old_ip)

        deadline = time.monotonic() + V2_JOB_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            job_payload = self._request_json_authed(
                f"/api/v2/lines/reconnect/jobs/{urllib.parse.quote(job_id, safe='')}",
                method="GET",
                timeout=30,
                csrf=True,
            )
            status = str(job_payload.get("status") or "").strip().lower()
            if status in {"queued", "running"}:
                time.sleep(V2_JOB_POLL_SECONDS)
                continue
            if status == "error" or job_payload.get("error"):
                return {
                    **job_payload,
                    "old_ip": old_ip,
                    "retryable": False,
                    "error": str(job_payload.get("error") or "换 IP 任务失败"),
                }
            return self._normalize_v2_change_result(job_payload, old_ip)

        logging.warning("Panel v2 reconnect job timed out for line %s", router_id)
        return {
            "old_ip": old_ip,
            "ip_pending": True,
            "error": "换 IP 已提交，但暂时无法确认结果。",
        }

    def get_target_ip(self, router_id: str, interface: str) -> str:
        if str(interface) != LEGACY_INTERFACE:
            raise IppanelError("新版面板线路标识无效，请重新打开机器列表。")
        return self._query_line_ip(str(router_id))

    def _query_line_ip(self, line_id: str) -> str:
        payload = self._request_json_authed(
            f"/api/v2/lines/{urllib.parse.quote(line_id, safe='')}/query",
            method="POST",
            json_data={},
            timeout=60,
            csrf=True,
        )
        if payload.get("error"):
            raise IppanelError(str(payload["error"]))
        return validate_public_ipv4(str(payload.get("public_ip") or payload.get("ip") or ""))

    def _query_catalog_product(self, product_ref: str) -> dict[str, Any]:
        payload = self._request_json_authed(
            f"/api/v2/catalog/{urllib.parse.quote(product_ref, safe='')}/query",
            method="POST",
            json_data={},
            timeout=60,
            csrf=True,
        )
        if payload.get("error"):
            raise IppanelError(str(payload["error"]))
        return payload

    def _normalize_lines_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        if payload.get("error"):
            return {
                "backend_mode": "legacy",
                "error": str(payload["error"]),
                "results": {},
                "errors": {"panel": str(payload["error"])},
                "zone_items": [],
            }
        raw_lines = payload.get("lines") or []
        if not isinstance(raw_lines, list):
            raise IppanelError("新版面板返回的线路列表格式无效。")

        results: dict[str, dict[str, str]] = {}
        errors: dict[str, str] = {}
        zone_items: list[dict[str, Any]] = []
        for raw_line in raw_lines:
            if not isinstance(raw_line, dict):
                continue
            line = dict(raw_line)
            line_id = str(line.get("line_id") or "").strip()
            product_ref = str(line.get("product_ref") or "").strip()
            if not line_id and product_ref:
                try:
                    catalog_data = self._query_catalog_product(product_ref)
                except IppanelError as exc:
                    line["status"] = "error"
                    line["status_message"] = str(exc)
                    catalog_data = {}
                if catalog_data:
                    line.update(catalog_data)
                    line_id = str(catalog_data.get("line_id") or "").strip()
            if not line_id:
                continue

            status = str(line.get("status") or "").strip().lower()
            status_message = str(
                line.get("status_message") or line.get("status_msg") or ""
            ).strip()
            can_reconnect = line.get("can_reconnect")
            if status in {"", "catalog"}:
                status = "ok" if can_reconnect else "query_only"
            elif status == "ok" and can_reconnect is False:
                status = "query_only"
            elif can_reconnect is True and status not in {"error", "blacklisted", "query_only"}:
                status = "ok"

            current_ip = str(line.get("public_ip") or line.get("ip") or "").strip()
            if current_ip:
                try:
                    current_ip = validate_public_ipv4(current_ip)
                except IppanelTransientError:
                    current_ip = ""
            if not current_ip and status != "error":
                try:
                    current_ip = self._query_line_ip(line_id)
                except IppanelError as exc:
                    status = "error"
                    status_message = status_message or str(exc)

            if status == "error" and status_message:
                errors[line_id] = status_message
            results[line_id] = {LEGACY_INTERFACE: current_ip}
            zone_items.append(
                {
                    "router_id": line_id,
                    "interface": LEGACY_INTERFACE,
                    "label": str(
                        line.get("label") or line.get("product_name") or ""
                    ).strip(),
                    "dedicated_ip": str(line.get("dedicated_ip") or "").strip(),
                    "status": status,
                    "status_msg": status_message,
                }
            )

        normalized: dict[str, Any] = {
            "backend_mode": "legacy",
            "results": results,
            "errors": errors,
            "zone_items": zone_items,
        }
        for key in (
            "daily_used",
            "daily_limit",
            "daily_unlimited",
            "total_changes",
        ):
            if key in payload:
                normalized[key] = payload[key]
        return normalized

    def _normalize_v2_change_result(
        self, payload: dict[str, Any], old_ip: str
    ) -> dict[str, Any]:
        result = dict(payload)
        result["old_ip"] = str(result.get("old_ip") or old_ip)
        candidate = str(
            result.get("new_ip") or result.get("public_ip") or result.get("ip") or ""
        ).strip()
        if candidate:
            try:
                candidate = validate_public_ipv4(candidate)
            except IppanelTransientError:
                candidate = ""
        if candidate:
            if candidate == old_ip:
                result["ip_unchanged"] = True
            else:
                result["new_ip"] = candidate
        elif not result.get("ip_unchanged"):
            result["ip_pending"] = True
        return result

    def _request_json_authed(
        self,
        path: str,
        method: str = "GET",
        json_data: dict[str, Any] | None = None,
        timeout: int = 30,
        csrf: bool = False,
    ) -> dict[str, Any]:
        auth_retried = False
        transient_attempt = 0
        while True:
            try:
                self.login()
                headers: dict[str, str] = {}
                if csrf:
                    if not self.csrf_token:
                        session = self._request_json(
                            "/api/v2/session", method="GET", timeout=30
                        )
                        self.csrf_token = str(session.get("csrf_token") or "").strip()
                        if not self.csrf_token:
                            raise IppanelError("新版面板没有返回 CSRF Token。")
                    headers["X-CSRF-Token"] = self.csrf_token
                return self._request_json(
                    path,
                    method=method,
                    json_data=json_data,
                    timeout=timeout,
                    extra_headers=headers,
                )
            except IppanelAuthExpired:
                if auth_retried:
                    raise
                logging.info("Panel session expired; logging in again")
                self.logged_in = False
                self.csrf_token = ""
                auth_retried = True
                continue
            except IppanelTransientError as exc:
                if transient_attempt >= len(PANEL_TRANSIENT_RETRY_DELAYS):
                    raise
                delay = PANEL_TRANSIENT_RETRY_DELAYS[transient_attempt]
                transient_attempt += 1
                logging.warning(
                    "Panel transient error on %s: %s; retrying in %s seconds",
                    path,
                    exc,
                    delay,
                )
                self.logged_in = False
                time.sleep(delay)

    def _request_json(
        self,
        path: str,
        method: str = "GET",
        json_data: dict[str, Any] | None = None,
        timeout: int = 30,
        extra_headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        response = self._request_raw(
            path,
            method=method,
            json_data=json_data,
            extra_headers=extra_headers,
            timeout=timeout,
        )
        if response.status == 401 or is_login_page(response.text):
            raise IppanelAuthExpired("Panel session expired.")
        if response.status == 429:
            raise IppanelRateLimited(path, retry_after_seconds(response.headers))
        if response.status in PANEL_TRANSIENT_HTTP_STATUS:
            raise IppanelTransientError(
                f"Panel request {path} failed with HTTP {response.status}."
            )
        if response.status >= 400:
            raise IppanelError(f"Panel request {path} failed with HTTP {response.status}.")
        try:
            data = json.loads(response.text)
        except json.JSONDecodeError as exc:
            snippet = response.text[:200].replace("\n", " ")
            raise IppanelError(f"Panel returned non-JSON response for {path}: {snippet}") from exc
        if not isinstance(data, dict):
            raise IppanelError(f"Panel returned unexpected JSON for {path}.")
        return data

    def _request_raw(
        self,
        path: str,
        method: str,
        json_data: dict[str, Any] | None = None,
        form_data: dict[str, str] | None = None,
        extra_headers: dict[str, str] | None = None,
        timeout: int = 30,
    ) -> HttpResponse:
        url = urllib.parse.urljoin(self.base_url + "/", path.lstrip("/"))
        headers = {
            "User-Agent": f"ippanelbot/{APP_VERSION}",
            "Accept": "application/json, text/plain, */*",
        }
        body: bytes | None = None
        if json_data is not None:
            body = json.dumps(json_data, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
        elif form_data is not None:
            body = urllib.parse.urlencode(form_data).encode("utf-8")
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        if extra_headers:
            headers.update(extra_headers)

        request = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=timeout) as response:
                raw = response.read()
                status = response.getcode()
                final_url = response.geturl()
                content_type = response.headers.get("Content-Type", "")
                response_headers = dict(response.headers.items())
                charset = response.headers.get_content_charset() or "utf-8"
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            status = exc.code
            final_url = exc.geturl()
            content_type = exc.headers.get("Content-Type", "")
            response_headers = dict(exc.headers.items())
            charset = exc.headers.get_content_charset() or "utf-8"
        except (urllib.error.URLError, TimeoutError, socket.timeout) as exc:
            reason = exc.reason if isinstance(exc, urllib.error.URLError) else exc
            raise IppanelTransientError(f"Panel network error: {reason}") from exc

        text = raw.decode(charset, errors="replace")
        return HttpResponse(
            status=status,
            final_url=final_url,
            content_type=content_type,
            headers=response_headers,
            text=text,
        )


def api_error_is_transient(message: str) -> bool:
    normalized = str(message or "").strip().lower()
    return any(
        marker in normalized
        for marker in ("內部錯誤", "内部错误", "internal error", "稍後再試", "稍后再试")
    )


def validate_public_ipv4(value: str) -> str:
    text = str(value or "").strip()
    try:
        parsed = ipaddress.ip_address(text)
    except ValueError as exc:
        raise IppanelTransientError(f"API 返回了无效 IP：{text or '空值'}") from exc
    if parsed.version != 4:
        raise IppanelTransientError(f"API 返回的不是 IPv4：{text}")
    return str(parsed)


class IppanelApiClient:
    def __init__(
        self,
        base_url: str,
        targets: tuple[ApiTarget, ...],
        query_cache_seconds: int = 60,
    ):
        self.mode = "api"
        self.base_url = base_url.rstrip("/")
        self.targets = targets
        self.targets_by_id = {target.target_id: target for target in targets}
        self.query_cache_seconds = max(0, query_cache_seconds)
        self._query_all_cache: dict[str, Any] | None = None
        self._query_all_cache_at = 0.0

    def _target(self, router_id: str, interface: str) -> ApiTarget:
        if str(interface) != API_INTERFACE:
            raise IppanelError("API 模式机器标识无效，请重新打开机器列表。")
        target = self.targets_by_id.get(str(router_id))
        if target is None:
            raise IppanelError("API 配置中没有找到这台机器，请检查 targets 文件。")
        return target

    def get_target_ip(self, router_id: str, interface: str) -> str:
        target = self._target(router_id, interface)
        payload = self._request_json(target, "/api/v1/getIP", timeout=30)
        if not payload.get("ok"):
            raise IppanelTransientError("查询 IP 未成功，请稍后再试。")
        return validate_public_ipv4(str(payload.get("ip") or ""))

    def target_label(self, router_id: str, interface: str) -> str:
        return self._target(router_id, interface).label

    def invalidate_cache(self) -> None:
        self._query_all_cache = None
        self._query_all_cache_at = 0.0

    def query_all(self, force: bool = False) -> dict[str, Any]:
        now = time.monotonic()
        if (
            not force
            and self._query_all_cache is not None
            and self.query_cache_seconds > 0
            and now - self._query_all_cache_at <= self.query_cache_seconds
        ):
            return dict(self._query_all_cache)

        results: dict[str, dict[str, str]] = {}
        errors: dict[str, str] = {}
        zone_items: list[dict[str, Any]] = []
        for target in self.targets:
            status = "ok"
            status_msg = ""
            current_ip = ""
            try:
                current_ip = self.get_target_ip(target.target_id, API_INTERFACE)
            except IppanelError as exc:
                status = "error"
                status_msg = str(exc)
                errors[target.target_id] = status_msg
            results[target.target_id] = {API_INTERFACE: current_ip}
            zone_items.append(
                {
                    "router_id": target.target_id,
                    "interface": API_INTERFACE,
                    "label": target.label,
                    "dedicated_ip": "",
                    "status": status,
                    "status_msg": status_msg,
                }
            )

        payload: dict[str, Any] = {
            "backend_mode": "api",
            "results": results,
            "errors": errors,
            "zone_items": zone_items,
        }
        self._query_all_cache = dict(payload)
        self._query_all_cache_at = now
        return payload

    def reconnect(self, router_id: str, interface: str) -> dict[str, Any]:
        target = self._target(router_id, interface)
        self.invalidate_cache()
        payload = self._request_json(target, "/api/v1/changeIP/", timeout=30)
        if not payload.get("ok"):
            raise IppanelError(str(payload.get("error") or "API 未接受换 IP 请求。"))
        return payload

    def _request_json(self, target: ApiTarget, path: str, timeout: int) -> dict[str, Any]:
        url = urllib.parse.urljoin(self.base_url + "/", path.lstrip("/"))
        request = urllib.request.Request(
            url,
            data=b"",
            headers={
                "Authorization": f"Bearer {target.token}",
                "Accept": "application/json",
                "User-Agent": f"ippanelbot/{APP_VERSION}",
            },
            method="POST",
        )
        response_headers: dict[str, str] = {}
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                raw = response.read()
                status = response.getcode()
                response_headers = dict(response.headers.items())
                charset = response.headers.get_content_charset() or "utf-8"
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            status = exc.code
            response_headers = dict(exc.headers.items())
            charset = exc.headers.get_content_charset() or "utf-8"
        except (urllib.error.URLError, TimeoutError, socket.timeout) as exc:
            reason = exc.reason if isinstance(exc, urllib.error.URLError) else exc
            raise IppanelTransientError(f"API 网络错误：{reason}") from exc

        text = raw.decode(charset, errors="replace")
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            snippet = text[:200].replace("\n", " ")
            raise IppanelTransientError(f"API 返回了非 JSON 内容：{snippet}") from exc
        if not isinstance(payload, dict):
            raise IppanelTransientError("API 返回了无法识别的 JSON。")

        error_message = str(payload.get("error") or "").strip()
        if status == 429:
            raise IppanelRateLimited(path, retry_after_seconds(response_headers))
        if status >= 500:
            raise IppanelTransientError(error_message or f"API HTTP {status}")
        if status >= 400 or error_message:
            message = error_message or f"API HTTP {status}"
            if api_error_is_transient(message):
                raise IppanelTransientError(message)
            raise IppanelError(message)
        return payload


class CloudflareClient:
    def __init__(self, api_token: str, zone_id: str):
        self.api_token = api_token.strip()
        self.zone_id = zone_id.strip()
        self.base_url = "https://api.cloudflare.com/client/v4/"

    @property
    def configured(self) -> bool:
        return bool(self.api_token and self.zone_id)

    def find_a_record(self, hostname: str) -> dict[str, Any] | None:
        hostname = validate_hostname(hostname)
        path = f"zones/{urllib.parse.quote(self.zone_id)}/dns_records"
        params = urllib.parse.urlencode({"type": "A", "name": hostname, "per_page": "5"})
        data = self._request("GET", f"{path}?{params}")
        records = data.get("result") or []
        if not isinstance(records, list):
            raise DdnsError("Cloudflare returned unexpected DNS record list.")
        for record in records:
            if (
                isinstance(record, dict)
                and str(record.get("type") or "").upper() == "A"
                and str(record.get("name") or "").lower().rstrip(".") == hostname
            ):
                return record
        return None

    def create_a_record(self, hostname: str, ip: str, ttl: int = 60) -> dict[str, Any]:
        hostname = validate_hostname(hostname)
        path = f"zones/{urllib.parse.quote(self.zone_id)}/dns_records"
        data = self._request(
            "POST",
            path,
            {
                "type": "A",
                "name": hostname,
                "content": ip,
                "ttl": normalize_cloudflare_ttl(ttl),
                "proxied": False,
            },
        )
        record = data.get("result") or {}
        if not isinstance(record, dict) or not record.get("id"):
            raise DdnsError("Cloudflare did not return created DNS record id.")
        return record

    def update_a_record(
        self,
        record_id: str,
        hostname: str,
        ip: str,
        ttl: int = 1,
        proxied: bool = False,
    ) -> dict[str, Any]:
        hostname = validate_hostname(hostname)
        if not record_id:
            raise DdnsError("Cloudflare DNS record id is missing.")
        path = (
            f"zones/{urllib.parse.quote(self.zone_id)}/dns_records/"
            f"{urllib.parse.quote(record_id)}"
        )
        data = self._request(
            "PATCH",
            path,
            {
                "type": "A",
                "name": hostname,
                "content": ip,
                "ttl": normalize_cloudflare_ttl(ttl),
                "proxied": bool(proxied),
            },
        )
        record = data.get("result") or {}
        if not isinstance(record, dict):
            raise DdnsError("Cloudflare returned unexpected DNS record response.")
        return record

    def _request(
        self, method: str, path: str, body: dict[str, Any] | None = None, timeout: int = 20
    ) -> dict[str, Any]:
        if not self.configured:
            raise DdnsError("Cloudflare API Token 或 Zone ID 未配置。")
        url = urllib.parse.urljoin(self.base_url, path)
        headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        data = json.dumps(body).encode("utf-8") if body is not None else None
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                payload = json.loads(raw.decode("utf-8", errors="replace"))
            except json.JSONDecodeError as parse_exc:
                raise DdnsError(f"Cloudflare API failed with HTTP {exc.code}.") from parse_exc
            raise DdnsError(cloudflare_error_message(payload, f"HTTP {exc.code}")) from exc
        except (urllib.error.URLError, TimeoutError, socket.timeout) as exc:
            reason = exc.reason if isinstance(exc, urllib.error.URLError) else exc
            raise DdnsError(f"Cloudflare network error: {reason}") from exc

        try:
            payload = json.loads(raw.decode("utf-8", errors="replace"))
        except json.JSONDecodeError as exc:
            raise DdnsError("Cloudflare returned non-JSON response.") from exc
        if not payload.get("success"):
            raise DdnsError(cloudflare_error_message(payload, "Cloudflare API failed."))
        return payload


def cloudflare_error_message(payload: dict[str, Any], fallback: str) -> str:
    errors = payload.get("errors") if isinstance(payload, dict) else None
    if isinstance(errors, list) and errors:
        messages = []
        for item in errors:
            if isinstance(item, dict):
                messages.append(str(item.get("message") or item))
        if messages:
            return "Cloudflare API error: " + "; ".join(messages[:3])
    return fallback


def post_relay_report(
    binding: RelayBinding,
    new_ip: str,
    old_ip: str = "",
    timeout: int = 20,
) -> None:
    receiver_url = validate_relay_url(binding.receiver_url)
    payload: dict[str, Any] = {
        "reporter": binding.reporter,
        "target_name": binding.receiver_target_name,
        "match_mode": normalize_relay_match_mode(binding.match_mode),
        "ip": new_ip,
        "ts": int(time.time()),
        "nonce": secrets.token_hex(12),
    }
    if old_ip:
        payload["old_ip"] = old_ip
    raw_body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    signature = hmac.new(binding.secret.encode("utf-8"), raw_body, sha256).hexdigest()
    request = urllib.request.Request(
        receiver_url,
        data=raw_body,
        headers={
            "Content-Type": "application/json",
            "X-IPPanelReceiver-Signature": f"sha256={signature}",
            "User-Agent": f"ippanelbot/{APP_VERSION}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
            status = response.getcode()
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        status = exc.code
    except (urllib.error.URLError, TimeoutError, socket.timeout) as exc:
        reason = exc.reason if isinstance(exc, urllib.error.URLError) else exc
        raise RelaySyncError(f"receiver network error: {reason}") from exc

    try:
        data = json.loads(raw.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        snippet = raw[:200].decode("utf-8", errors="replace").replace("\n", " ")
        raise RelaySyncError(f"receiver returned non-JSON response: HTTP {status}: {snippet}") from exc
    if status >= 400 or not data.get("ok"):
        detail = data.get("detail") or data.get("error") or f"HTTP {status}"
        raise RelaySyncError(str(detail))


class TelegramApi:
    def __init__(self, token: str):
        self.base_url = f"https://api.telegram.org/bot{token}/"

    def get_updates(self, offset: int | None, timeout: int = 50) -> list[dict[str, Any]]:
        payload: dict[str, Any] = {
            "timeout": timeout,
            "allowed_updates": json.dumps(["message", "callback_query"]),
        }
        if offset is not None:
            payload["offset"] = offset
        data = self._call("getUpdates", payload, timeout=timeout + 3)
        return data.get("result", []) if data.get("ok") else []

    def set_my_commands(self, commands: list[dict[str, str]]) -> None:
        payload = {
            "commands": json.dumps(commands, ensure_ascii=False),
        }
        self._call("setMyCommands", payload, timeout=12)

    def send_message(
        self,
        chat_id: int,
        text: str,
        reply_markup: dict[str, Any] | None = None,
        parse_mode: str | None = None,
    ) -> None:
        payload: dict[str, Any] = {"chat_id": chat_id, "text": text}
        if parse_mode:
            payload["parse_mode"] = parse_mode
        if reply_markup:
            payload["reply_markup"] = json.dumps(reply_markup, ensure_ascii=False)
        self._call("sendMessage", payload, timeout=12)

    def send_photo(
        self,
        chat_id: int,
        photo_path: Path,
        caption: str = "",
        reply_markup: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        fields: dict[str, str] = {"chat_id": str(chat_id)}
        if caption:
            fields["caption"] = caption
        if reply_markup:
            fields["reply_markup"] = json.dumps(reply_markup, ensure_ascii=False)
        return self._call_multipart(
            "sendPhoto",
            fields=fields,
            file_field="photo",
            file_path=photo_path,
            timeout=12,
        )

    def send_photo_file_id(
        self,
        chat_id: int,
        file_id: str,
        caption: str = "",
        reply_markup: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"chat_id": chat_id, "photo": file_id}
        if caption:
            payload["caption"] = caption
        if reply_markup:
            payload["reply_markup"] = json.dumps(reply_markup, ensure_ascii=False)
        return self._call("sendPhoto", payload, timeout=12)

    def edit_message_text(
        self,
        chat_id: int,
        message_id: int,
        text: str,
        reply_markup: dict[str, Any] | None = None,
        parse_mode: str | None = None,
    ) -> None:
        payload: dict[str, Any] = {"chat_id": chat_id, "message_id": message_id, "text": text}
        if parse_mode:
            payload["parse_mode"] = parse_mode
        if reply_markup:
            payload["reply_markup"] = json.dumps(reply_markup, ensure_ascii=False)
        self._call("editMessageText", payload, timeout=12)

    def answer_callback_query(
        self, callback_query_id: str, text: str = "", show_alert: bool = False
    ) -> None:
        payload: dict[str, Any] = {
            "callback_query_id": callback_query_id,
            "show_alert": "true" if show_alert else "false",
        }
        if text:
            payload["text"] = text
        self._call("answerCallbackQuery", payload, timeout=8)

    def _call_multipart(
        self,
        method: str,
        fields: dict[str, str],
        file_field: str,
        file_path: Path,
        timeout: int,
    ) -> dict[str, Any]:
        url = self.base_url + method
        boundary = f"----ippanelbot{int(time.time() * 1000)}"
        body_parts: list[bytes] = []
        for name, value in fields.items():
            body_parts.extend(
                [
                    f"--{boundary}\r\n".encode("utf-8"),
                    f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode("utf-8"),
                    str(value).encode("utf-8"),
                    b"\r\n",
                ]
            )
        filename = file_path.name or "panel.png"
        file_bytes = file_path.read_bytes()
        body_parts.extend(
            [
                f"--{boundary}\r\n".encode("utf-8"),
                (
                    f'Content-Disposition: form-data; name="{file_field}"; '
                    f'filename="{filename}"\r\n'
                ).encode("utf-8"),
                b"Content-Type: image/png\r\n\r\n",
                file_bytes,
                b"\r\n",
                f"--{boundary}--\r\n".encode("utf-8"),
            ]
        )
        body = b"".join(body_parts)
        request = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                data = json.loads(raw.decode("utf-8", errors="replace"))
            except json.JSONDecodeError as parse_exc:
                raise TelegramApiError(f"Telegram API {method} failed with HTTP {exc.code}") from parse_exc
            description = data.get("description") or f"HTTP {exc.code}"
            raise TelegramApiError(f"Telegram API {method} failed: {description}") from exc
        except (urllib.error.URLError, TimeoutError, socket.timeout) as exc:
            reason = exc.reason if isinstance(exc, urllib.error.URLError) else exc
            raise TelegramNetworkError(f"Telegram network error: {reason}") from exc

        data = json.loads(raw.decode("utf-8", errors="replace"))
        if not data.get("ok"):
            raise TelegramApiError(f"Telegram API {method} failed: {data.get('description', data)}")
        return data

    def _call(self, method: str, payload: dict[str, Any], timeout: int) -> dict[str, Any]:
        url = self.base_url + method
        body = urllib.parse.urlencode(payload).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                data = json.loads(raw.decode("utf-8", errors="replace"))
            except json.JSONDecodeError as parse_exc:
                raise TelegramApiError(f"Telegram API {method} failed with HTTP {exc.code}") from parse_exc
            description = data.get("description") or f"HTTP {exc.code}"
            raise TelegramApiError(f"Telegram API {method} failed: {description}") from exc
        except (urllib.error.URLError, TimeoutError, socket.timeout) as exc:
            reason = exc.reason if isinstance(exc, urllib.error.URLError) else exc
            raise TelegramNetworkError(f"Telegram network error: {reason}") from exc

        data = json.loads(raw.decode("utf-8", errors="replace"))
        if not data.get("ok"):
            raise TelegramApiError(f"Telegram API {method} failed: {data.get('description', data)}")
        return data


def parse_zones(payload: dict[str, Any]) -> list[ZoneItem]:
    results = payload.get("results") or {}
    errors = payload.get("errors") or {}
    zone_items = payload.get("zone_items") or []
    zones: list[ZoneItem] = []

    if isinstance(zone_items, list) and zone_items:
        for item in zone_items:
            if not isinstance(item, dict):
                continue
            router_id = str(item.get("router_id") or "").strip()
            interface = str(item.get("interface") or "").strip()
            if not router_id or not interface:
                continue
            label = str(item.get("label") or item.get("product_name") or "").strip()
            dedicated_ip = str(item.get("dedicated_ip") or "").strip()
            status = str(item.get("status") or "unknown").strip()
            status_msg = str(item.get("status_msg") or "").strip()
            ip_map = get_key(results, router_id) or {}
            current_ip = str(get_key(ip_map, interface) or "").strip()
            panel_error = str(get_key(errors, router_id) or "").strip()
            if panel_error:
                current_ip = ""
                if status == "ok":
                    status = "error"
                if not status_msg:
                    status_msg = panel_error
            zones.append(
                ZoneItem(
                    router_id=router_id,
                    interface=interface,
                    label=label,
                    dedicated_ip=dedicated_ip,
                    current_ip=current_ip,
                    status=status,
                    status_msg=status_msg,
                )
            )
        return zones

    if isinstance(results, dict):
        for router_id, ip_map in results.items():
            if not isinstance(ip_map, dict):
                continue
            for interface, current_ip in ip_map.items():
                rid = str(router_id)
                iface = str(interface)
                zones.append(
                    ZoneItem(
                        router_id=rid,
                        interface=iface,
                        label=f"Router {rid} / {iface}",
                        dedicated_ip="",
                        current_ip=str(current_ip or ""),
                        status="ok",
                        status_msg="",
                    )
                )
    return zones


def find_zone(zones: list[ZoneItem], router_id: str, interface: str) -> ZoneItem | None:
    for zone in zones:
        if zone.router_id == str(router_id) and zone.interface == str(interface):
            return zone
    return None


def quota_text(payload: dict[str, Any]) -> str:
    if payload.get("backend_mode") == "api":
        return "API 模式：可用次数和换 IP CD 会在提交成功后返回"
    used = payload.get("daily_used")
    limit = payload.get("daily_limit")
    if used is None and limit is None:
        return "今日次数：面板未返回"
    used_int = parse_int(used, 0)
    limit_int = parse_int(limit, 0)
    if limit_int > 0:
        remaining = max(0, limit_int - used_int)
        return f"今日次数：已用 {used_int} / {limit_int}，剩余 {remaining}"
    return f"今日次数：已用 {used_int} / 无限"


def status_label(zone: ZoneItem) -> str:
    if zone.status == "ok":
        return "可更换"
    if zone.status in ("query_only", "blacklisted"):
        return "仅查询"
    if zone.status == "error":
        return zone.status_msg or "查询失败"
    if zone.status_msg:
        return zone.status_msg
    return zone.status or "未知"


def format_zone_line(index: int, zone: ZoneItem) -> list[str]:
    lines = [tg_bold(f"{index}. {zone.display_name}")]
    if zone.dedicated_ip:
        lines.append(f"   内网/绑定 IP：{zone.dedicated_ip}")
    lines.append(f"   当前公网 IP：{zone.current_ip or '未找到'}")
    lines.append(f"   状态：{status_label(zone)}")
    return lines


def format_status_message(payload: dict[str, Any], zones: list[ZoneItem], page: int = 0) -> str:
    lines = [tg_bold("当前 IP 状态"), quota_text(payload), ""]
    if not zones:
        lines.append("没有从面板查到机器。")
        return "\n".join(lines)

    page = clamp_page(page, len(zones))
    pages = total_pages(len(zones))
    if pages > 1:
        lines.append(f"第 {page + 1}/{pages} 页，共 {len(zones)} 台")
        lines.append("")

    start = page * PAGE_SIZE
    page_zones = zones[start : start + PAGE_SIZE]
    for offset, zone in enumerate(page_zones, start=1):
        index = start + offset
        lines.extend(format_zone_line(index, zone))
        lines.append("")
    return "\n".join(lines).strip()


def format_change_result(
    zone_before: ZoneItem | None,
    reconnect_data: dict[str, Any],
    payload_after: dict[str, Any] | None,
    zone_after: ZoneItem | None,
) -> str:
    if reconnect_data.get("ip_pending"):
        name = zone_before.display_name if zone_before else "目标机器"
        old_ip = reconnect_data.get("old_ip") or (zone_before.current_ip if zone_before else "")
        lines = [tg_bold(f"{name} 换 IP 已提交，但暂时无法确认")]
        if old_ip:
            lines.append(f"换 IP 前：{old_ip}")
        if reconnect_data.get("error"):
            lines.append(f"最近状态：{reconnect_data.get('error')}")
        lines.append("Bot 不会重复提交，请稍后使用 /ip 查询。")
        return "\n".join(lines)
    if reconnect_data.get("error"):
        name = zone_before.display_name if zone_before else "目标机器"
        return f"{tg_bold(f'{name} 更换失败')}：{reconnect_data.get('error')}"
    if reconnect_data.get("ip_unchanged"):
        name = zone_before.display_name if zone_before else "目标机器"
        lines = [tg_bold(f"{name} 多次尝试后 IP 仍未变化。")]
        old_ip = reconnect_data.get("old_ip") or (zone_before.current_ip if zone_before else "")
        if old_ip:
            lines.append(f"当前 IP：{old_ip}")
        lines.append("面板通常不会消耗次数，或会自动返还次数。")
        if payload_after:
            lines.append(quota_text(payload_after))
        return "\n".join(lines)

    name = (
        zone_after.display_name
        if zone_after
        else zone_before.display_name
        if zone_before
        else "目标机器"
    )
    old_ip = reconnect_data.get("old_ip") or (zone_before.current_ip if zone_before else "")
    new_ip = reconnect_data.get("new_ip") or (zone_after.current_ip if zone_after else "")

    lines = [tg_bold(f"{name} 更换请求已完成")]
    if old_ip:
        lines.append(f"旧 IP：{old_ip}")
    if new_ip:
        lines.append(f"当前/新 IP：{new_ip}")
        lines.append(purity_link_line(str(new_ip)))
    elif reconnect_data.get("mac_mode"):
        lines.append("新 IP：面板已提交，请稍后再用 /ip 查询确认")
    else:
        lines.append("新 IP：面板未返回，请稍后再用 /ip 查询确认")
    if reconnect_data.get("ip_unchanged"):
        lines.append("提示：面板返回 IP 未变化，次数通常会返还。")
    if payload_after:
        lines.append(quota_text(payload_after))
    if reconnect_data.get("total_changes"):
        lines.append(f"面板累计更换：{reconnect_data.get('total_changes')}")
    return "\n".join(lines)


def should_retry_change_result(reconnect_data: dict[str, Any]) -> bool:
    if reconnect_data.get("ip_pending"):
        return False
    if reconnect_data.get("retryable") is False:
        return False
    if reconnect_data.get("error"):
        return True
    if reconnect_data.get("ip_unchanged"):
        return True
    return False


def change_retry_reason(reconnect_data: dict[str, Any]) -> str:
    if reconnect_data.get("ip_pending"):
        return "换 IP 已提交，但暂时无法确认"
    if reconnect_data.get("error"):
        return str(reconnect_data.get("error"))
    if reconnect_data.get("ip_unchanged"):
        return "IP 未变化，次数通常未消耗或已返还"
    return "更换未成功"


def api_confirmation_delay(check_count: int, poll_interval: int) -> int:
    index = max(0, int(check_count))
    if index < len(API_CONFIRM_BACKOFF_SECONDS):
        return API_CONFIRM_BACKOFF_SECONDS[index]
    return max(5, int(poll_interval))


def format_api_change_accepted(
    target_name: str,
    old_ip: str,
    uses_left: int | None,
    next_allowed_at: int | None,
    tz,
    timezone_name: str,
) -> str:
    lines = [tg_bold(f"{target_name} 换 IP 请求已受理"), f"旧 IP：{old_ip}"]
    if uses_left is not None:
        lines.append(f"API 可用次数：{uses_left}")
    if next_allowed_at:
        lines.append(
            f"下次允许换 IP：{format_run_time(next_allowed_at, tz, timezone_name)}"
        )
    lines.extend(["", "正在后台等待并确认新 IP，不会重复提交换 IP。"])
    return "\n".join(lines)


def format_api_change_confirmed(
    operation: ApiChangeOperation, new_ip: str, tz, timezone_name: str
) -> str:
    elapsed = max(0, int(time.time()) - operation.requested_at)
    lines = [
        tg_bold(f"{operation.target_name} 换 IP 已完成"),
        f"旧 IP：{operation.old_ip}",
        f"新 IP：{new_ip}",
        purity_link_line(new_ip),
        f"确认耗时：{elapsed} 秒",
    ]
    if operation.api_uses_left is not None:
        lines.append(f"API 可用次数：{operation.api_uses_left}")
    if operation.next_allowed_at:
        lines.append(
            "下次允许换 IP："
            f"{format_run_time(operation.next_allowed_at, tz, timezone_name)}"
        )
    return "\n".join(lines)


def callback_data(action: str, router_id: str, interface: str) -> str:
    return "|".join(
        [
            action,
            urllib.parse.quote(str(router_id), safe=""),
            urllib.parse.quote(str(interface), safe=""),
        ]
    )


def parse_callback_data(data: str) -> tuple[str, str, str]:
    parts = data.split("|", 2)
    if len(parts) != 3:
        raise ValueError("bad callback data")
    return (
        parts[0],
        urllib.parse.unquote(parts[1]),
        urllib.parse.unquote(parts[2]),
    )


def bot_command_menu(ddns_enabled: bool) -> list[dict[str, str]]:
    commands = [
        {"command": "start", "description": "打开主面板"},
        {"command": "ip", "description": "查询 IP"},
        {"command": "change", "description": "更换 IP"},
        {"command": "jobs", "description": "任务列表"},
        {"command": "canceljob", "description": "取消任务"},
    ]
    if ddns_enabled:
        commands.extend(
            [
                {"command": "ddns", "description": "DDNS 管理"},
                {"command": "ddnsdel", "description": "删除 DDNS 绑定"},
            ]
        )
    commands.extend(
        [
            {"command": "cancel", "description": "取消当前输入"},
            {"command": "help", "description": "帮助"},
        ]
    )
    return commands


class BotApp:
    def __init__(self, config: Config):
        self.config = config
        self.telegram = TelegramApi(config.telegram_bot_token)
        self.store = BotStore(config.db_path)
        self.panel = make_panel_client(config)
        self.api_panel = (
            self.panel
            if isinstance(self.panel, IppanelApiClient)
            else IppanelApiClient(
                config.ippanel_base_url,
                config.ippanel_api_targets,
                query_cache_seconds=0,
            )
            if config.ippanel_api_targets
            else None
        )
        self.stop_requested = False
        self.changing: set[tuple[str, str]] = set()
        self.last_change_context: dict[tuple[str, str], ChangeContext] = {}
        self.pending_inputs: dict[int, dict[str, str]] = {}
        self.timezone = load_timezone(config.timezone_name)
        self.panel_photo_file_id = ""
        if not config.ddns_enabled:
            self.cloudflare = None
        else:
            self.cloudflare = CloudflareClient(config.cloudflare_api_token, config.cloudflare_zone_id)

    def run(self) -> None:
        logging.info(
            "Starting ippanelbot %s in %s mode", APP_VERSION, self.config.ippanel_mode
        )
        self.configure_bot_commands()
        self.send_startup_notice()
        offset: int | None = None
        while not self.stop_requested:
            try:
                self.run_due_api_change_confirmations()
                self.run_due_scheduled_changes()
                updates = self.telegram.get_updates(
                    offset=offset, timeout=self.config.poll_timeout_seconds
                )
                for update in updates:
                    offset = max(offset or 0, int(update["update_id"]) + 1)
                    self.handle_update(update)
                self.run_due_api_change_confirmations()
                self.run_due_scheduled_changes()
            except KeyboardInterrupt:
                self.stop_requested = True
            except TelegramNetworkError as exc:
                logging.warning("Telegram network issue: %s", exc)
                time.sleep(1)
            except TelegramError as exc:
                logging.warning("Telegram API issue: %s", exc)
                time.sleep(3)
            except Exception:
                logging.exception("Main loop error")
                time.sleep(5)

    def configure_bot_commands(self) -> None:
        try:
            self.telegram.set_my_commands(bot_command_menu(self.config.ddns_enabled))
        except TelegramError as exc:
            logging.warning("Could not configure Telegram command menu: %s", exc)
        except Exception:
            logging.exception("Unexpected error while configuring Telegram command menu")

    def send_startup_notice(self) -> None:
        for chat_id in sorted(self.config.allowed_chat_ids):
            try:
                self.send_start_panel(chat_id)
            except TelegramError as exc:
                logging.warning("Could not send startup notice to %s: %s", chat_id, exc)
            except Exception:
                logging.exception("Unexpected error while sending startup notice to %s", chat_id)

    def request_stop(self, signum: int, _frame: Any) -> None:
        logging.info("Received signal %s; stopping", signum)
        self.stop_requested = True

    def handle_update(self, update: dict[str, Any]) -> None:
        if "message" in update:
            self.handle_message(update["message"])
        elif "callback_query" in update:
            self.handle_callback(update["callback_query"])

    def is_authorized(self, chat_id: int) -> bool:
        return bool(self.config.allowed_chat_ids) and chat_id in self.config.allowed_chat_ids

    def handle_message(self, message: dict[str, Any]) -> None:
        chat = message.get("chat") or {}
        chat_id = int(chat.get("id"))
        text = (message.get("text") or "").strip()
        mapped_command = BUTTON_COMMANDS.get(text)

        command = (
            mapped_command
            if mapped_command
            else text.split(maxsplit=1)[0].split("@", 1)[0].lower()
            if text
            else ""
        )
        if not self.is_authorized(chat_id):
            self.telegram.send_message(chat_id, "未授权。")
            return

        if chat_id in self.pending_inputs and not mapped_command and not text.startswith("/"):
            self.handle_schedule_input(chat_id, text)
            return

        if command == "/start":
            self.send_start_panel(chat_id)
        elif command == "/help":
            self.send_help_panel(chat_id)
        elif command in ("/ip", "/status", "/quota"):
            self.send_status(chat_id)
        elif command == "/change":
            self.send_change_menu(chat_id)
        elif command == "/jobs":
            self.send_jobs(chat_id)
        elif command == "/ddns":
            self.send_ddns_menu(chat_id)
        elif command == "/ddnsdel":
            self.handle_ddns_delete(chat_id, text)
        elif command == "/canceljob":
            self.handle_cancel_job(chat_id, text)
        elif command == "/cancel":
            self.pending_inputs.pop(chat_id, None)
            self.telegram.send_message(chat_id, "已取消当前输入。")
        else:
            self.telegram.send_message(chat_id, self.help_text())

    def handle_callback(self, callback: dict[str, Any]) -> None:
        callback_id = str(callback.get("id"))
        message = callback.get("message") or {}
        chat_id = int((message.get("chat") or {}).get("id"))
        message_id = int(message.get("message_id"))
        editable_message_id = message_id if message.get("text") is not None else None

        if not self.is_authorized(chat_id):
            self.telegram.answer_callback_query(callback_id, "未授权", show_alert=True)
            return

        try:
            action, router_id, interface = parse_callback_data(str(callback.get("data") or ""))
        except ValueError:
            self.telegram.answer_callback_query(callback_id, "按钮数据无效，请重新发送 /change")
            return

        if action == "cmd_ip":
            self.telegram.answer_callback_query(callback_id)
            self.send_status(chat_id)
        elif action == "ip_page":
            self.telegram.answer_callback_query(callback_id)
            self.send_status(chat_id, parse_int(router_id, 0), editable_message_id)
        elif action == "relay_status":
            self.telegram.answer_callback_query(callback_id)
            self.send_relay_status(chat_id, parse_int(router_id, 0), editable_message_id)
        elif action == "relay_page":
            self.telegram.answer_callback_query(callback_id)
            self.send_relay_status(chat_id, parse_int(router_id, 0), editable_message_id)
        elif action == "relay_test":
            self.telegram.answer_callback_query(callback_id, "开始测试")
            self.test_relay_sync(chat_id, router_id, interface, editable_message_id)
        elif action == "cmd_change":
            self.telegram.answer_callback_query(callback_id)
            self.send_change_menu(chat_id)
        elif action == "change_page":
            self.telegram.answer_callback_query(callback_id)
            self.send_change_menu(chat_id, parse_int(router_id, 0), editable_message_id)
        elif action == "cmd_jobs":
            self.telegram.answer_callback_query(callback_id)
            self.send_jobs(chat_id)
        elif action == "cmd_help":
            self.telegram.answer_callback_query(callback_id)
            self.send_help_panel(chat_id)
        elif action == "cmd_ddns":
            self.telegram.answer_callback_query(callback_id)
            self.send_ddns_menu(chat_id, editable_message_id)
        elif action == "ddns_add":
            self.telegram.answer_callback_query(callback_id)
            self.send_ddns_pick_menu(chat_id, 0, editable_message_id)
        elif action == "ddns_pick_page":
            self.telegram.answer_callback_query(callback_id)
            self.send_ddns_pick_menu(chat_id, parse_int(router_id, 0), editable_message_id)
        elif action == "ddns_pick":
            self.telegram.answer_callback_query(callback_id)
            self.ask_ddns_hostname(chat_id, editable_message_id, router_id, interface)
        elif action == "ddns_list":
            self.telegram.answer_callback_query(callback_id)
            self.send_ddns_list(chat_id, editable_message_id)
        elif action == "ddns_sync":
            self.telegram.answer_callback_query(callback_id, "开始同步")
            self.sync_all_ddns(chat_id, editable_message_id)
        elif action == "pick":
            self.telegram.answer_callback_query(callback_id)
            self.show_change_modes(chat_id, message_id, router_id, interface)
        elif action == "now":
            self.telegram.answer_callback_query(callback_id)
            self.show_confirm(chat_id, message_id, router_id, interface)
        elif action == "delay":
            self.telegram.answer_callback_query(callback_id)
            self.ask_delay_seconds(chat_id, message_id, router_id, interface)
        elif action in ("at", "plan"):
            self.telegram.answer_callback_query(callback_id)
            self.show_plan_type_menu(chat_id, message_id, router_id, interface)
        elif action == "plan_once":
            self.telegram.answer_callback_query(callback_id)
            self.ask_plan_input(chat_id, message_id, router_id, interface, "once")
        elif action == "plan_days":
            self.telegram.answer_callback_query(callback_id)
            self.ask_plan_input(chat_id, message_id, router_id, interface, "every_days")
        elif action == "plan_weekly":
            self.telegram.answer_callback_query(callback_id)
            self.ask_plan_input(chat_id, message_id, router_id, interface, "weekly")
        elif action == "plan_monthly":
            self.telegram.answer_callback_query(callback_id)
            self.ask_plan_input(chat_id, message_id, router_id, interface, "monthly")
        elif action == "confirm":
            self.telegram.answer_callback_query(callback_id, "开始更换")
            self.perform_change(chat_id, message_id, router_id, interface)
        elif action == "cancel":
            self.telegram.answer_callback_query(callback_id, "已取消")
            self.telegram.edit_message_text(chat_id, message_id, "已取消更换。")
        elif action == "noop":
            self.telegram.answer_callback_query(callback_id, "当前页")
        else:
            self.telegram.answer_callback_query(callback_id, "未知操作，请重新发送 /change")

    def help_text(self) -> str:
        mode_label = "API Token" if self.config.ippanel_mode == "api" else "账号登录"
        return "\n".join(
            [
                "IPPanelBot",
                f"当前模式：{mode_label}",
                "",
                "/ip - 查询当前机器和 IP",
                "/change - 选择机器，立即/延时/计划任务更换 IP",
                "/jobs - 查看未执行的延时/计划任务",
                "/canceljob 1 - 按 /jobs 中的序号取消任务",
                "/cancel - 取消当前输入",
            ]
        )

    def send_start_panel(self, chat_id: int) -> None:
        mode_label = "API Token" if self.config.ippanel_mode == "api" else "账号登录"
        caption = f"BoilのIP管理Panel\n当前模式：{mode_label}\n请选择下方按钮操作。"
        image_path = self.config.panel_image_path
        if image_path.exists():
            if self.panel_photo_file_id:
                try:
                    self.telegram.send_photo_file_id(
                        chat_id,
                        self.panel_photo_file_id,
                        caption=caption,
                        reply_markup=panel_keyboard(self.config.ddns_enabled),
                    )
                    return
                except TelegramApiError as exc:
                    logging.warning("Cached panel image file_id failed; uploading again: %s", exc)
                    self.panel_photo_file_id = ""
                except TelegramNetworkError as exc:
                    logging.warning("Failed to send cached panel image; falling back to text: %s", exc)
                    self.telegram.send_message(
                        chat_id, caption, reply_markup=panel_keyboard(self.config.ddns_enabled)
                    )
                    return
            try:
                response = self.telegram.send_photo(
                    chat_id,
                    image_path,
                    caption=caption,
                    reply_markup=panel_keyboard(self.config.ddns_enabled),
                )
                self.panel_photo_file_id = telegram_photo_file_id(response)
                return
            except TelegramNetworkError as exc:
                logging.warning("Failed to send panel image; falling back to text: %s", exc)
            except TelegramError as exc:
                logging.warning("Failed to send panel image; falling back to text: %s", exc)
            except Exception:
                logging.exception("Unexpected error while sending panel image")
        self.telegram.send_message(
            chat_id, caption, reply_markup=panel_keyboard(self.config.ddns_enabled)
        )

    def send_help_panel(self, chat_id: int) -> None:
        mode_label = "API Token" if self.config.ippanel_mode == "api" else "账号登录"
        lines = [
            "可用操作",
            f"当前模式：{mode_label}",
            "查询 IP：查看当前机器和公网 IP",
            "更换 IP：立即、延时或计划任务更换",
            "任务列表：查看和取消未执行任务",
        ]
        if self.config.ddns_enabled:
            lines.append("DDNS：给单台 VPS 绑定并同步 Cloudflare A 记录")
        lines.append("输入计划或 DDNS 配置时可发送 /cancel 取消当前输入")
        text = "\n".join(lines)
        self.telegram.send_message(
            chat_id, text, reply_markup=panel_keyboard(self.config.ddns_enabled)
        )

    def ddns_config_error(self) -> str:
        if not self.config.ddns_enabled:
            return "DDNS 未启用。请先运行 sudo boil config 开启 DDNS。"
        if not self.cloudflare or not self.cloudflare.configured:
            return "DDNS 已开启，但 Cloudflare API Token 或 Zone ID 未配置。请运行 sudo boil config。"
        return ""

    def ddns_menu_keyboard(self) -> dict[str, Any]:
        return {
            "inline_keyboard": [
                [
                    {"text": "添加/修改绑定", "callback_data": callback_data("ddns_add", "", "")},
                    {"text": "绑定列表", "callback_data": callback_data("ddns_list", "", "")},
                ],
                [
                    {"text": "手动同步", "callback_data": callback_data("ddns_sync", "", "")},
                    {"text": "帮助", "callback_data": callback_data("cmd_help", "", "")},
                ],
            ]
        }

    def send_ddns_menu(self, chat_id: int, message_id: int | None = None) -> None:
        error = self.ddns_config_error()
        if error:
            self.send_or_edit(chat_id, message_id, error)
            return
        count = len(self.store.list_ddns_bindings(chat_id))
        text = "\n".join(
            [
                "DDNS 管理",
                "Provider：Cloudflare",
                f"已绑定：{count} 台 VPS",
                "",
                "添加绑定时只需要输入 hostname。",
                "删除绑定：/ddnsdel 1",
            ]
        )
        self.send_or_edit(chat_id, message_id, text, reply_markup=self.ddns_menu_keyboard())

    def send_ddns_pick_menu(
        self, chat_id: int, page: int = 0, message_id: int | None = None
    ) -> None:
        error = self.ddns_config_error()
        if error:
            self.send_or_edit(chat_id, message_id, error)
            return
        try:
            payload = self.panel.query_all()
            if payload.get("error"):
                self.send_or_edit(chat_id, message_id, f"查询失败：{payload.get('error')}")
                return
            zones = parse_zones(payload)
            if not zones:
                self.send_or_edit(chat_id, message_id, "没有从面板查到机器。")
                return
            page = clamp_page(page, len(zones))
            pages = total_pages(len(zones))
            lines = ["选择要配置 DDNS 的 VPS", ""]
            if pages > 1:
                lines.append(f"第 {page + 1}/{pages} 页，共 {len(zones)} 台")
                lines.append("")
            start = page * PAGE_SIZE
            page_zones = zones[start : start + PAGE_SIZE]
            for offset, zone in enumerate(page_zones, start=1):
                index = start + offset
                lines.extend(format_zone_line(index, zone))
                binding = self.store.get_ddns_binding_for_zone(
                    chat_id,
                    zone.router_id,
                    zone.interface,
                    target_name=zone.display_name,
                    previous_ip=zone.current_ip,
                )
                if binding:
                    lines.append(f"   DDNS：{binding.hostname}")
                lines.append("")

            rows = []
            for offset, zone in enumerate(page_zones, start=1):
                index = start + offset
                label = f"{index}. 配置 {zone.display_name}"
                rows.append(
                    [
                        {
                            "text": short_text(label, 60),
                            "callback_data": callback_data(
                                "ddns_pick", zone.router_id, zone.interface
                            ),
                        }
                    ]
                )
            rows.extend(pagination_rows("ddns_pick_page", page, len(zones)))
            rows.append([{"text": "返回", "callback_data": callback_data("cmd_ddns", "", "")}])
            self.send_or_edit(
                chat_id,
                message_id,
                "\n".join(lines).strip(),
                reply_markup={"inline_keyboard": rows},
            )
        except IppanelError as exc:
            self.send_or_edit(chat_id, message_id, f"面板请求失败：{exc}")
        except Exception as exc:
            logging.exception("DDNS pick menu failed")
            self.send_or_edit(chat_id, message_id, f"生成 DDNS 菜单失败：{exc}")

    def ask_ddns_hostname(
        self, chat_id: int, message_id: int | None, router_id: str, interface: str
    ) -> None:
        error = self.ddns_config_error()
        if error:
            self.send_or_edit(chat_id, message_id, error)
            return
        try:
            zone = self.query_zone_for_action(router_id, interface)
            if not zone:
                self.send_or_edit(chat_id, message_id, "面板里没有找到这台 VPS。")
                return
            self.pending_inputs[chat_id] = {
                "mode": "ddns_hostname",
                "router_id": zone.router_id,
                "interface": zone.interface,
                "target_name": zone.display_name,
            }
            self.send_or_edit(
                chat_id,
                message_id,
                "\n".join(
                    [
                        "请输入这台 VPS 要绑定的 hostname。",
                        f"目标：{zone.display_name}",
                        f"当前 IP：{zone.current_ip or '未找到'}",
                        "",
                        "例如：hk1.example.com",
                        "取消输入：/cancel",
                    ]
                ),
            )
        except IppanelError as exc:
            self.send_or_edit(chat_id, message_id, f"面板请求失败：{exc}")

    def send_ddns_list(self, chat_id: int, message_id: int | None = None) -> None:
        error = self.ddns_config_error()
        if error:
            self.send_or_edit(chat_id, message_id, error)
            return
        bindings = self.store.list_ddns_bindings(chat_id)
        if not bindings:
            self.send_or_edit(chat_id, message_id, "当前没有 DDNS 绑定。")
            return
        lines = ["DDNS 绑定列表"]
        for index, binding in enumerate(bindings, start=1):
            lines.append("")
            lines.append(f"{index}. {safe_target_name(binding.target_name, binding.router_id, binding.interface)}")
            lines.append(f"域名：{binding.hostname}")
            if binding.last_ip:
                lines.append(f"上次 IP：{binding.last_ip}")
            if binding.last_update_at:
                lines.append(
                    f"上次同步：{format_run_time(binding.last_update_at, self.timezone, self.config.timezone_name)}"
                )
            lines.append(f"删除：/ddnsdel {index}")
        self.send_or_edit(chat_id, message_id, "\n".join(lines))

    def send_or_edit(
        self,
        chat_id: int,
        message_id: int | None,
        text: str,
        reply_markup: dict[str, Any] | None = None,
        protect_autolinks: bool = True,
    ) -> None:
        if protect_autolinks:
            text = telegram_html(text)
            parse_mode = "HTML"
        else:
            parse_mode = None
        if message_id is None:
            self.telegram.send_message(
                chat_id, text, reply_markup=reply_markup, parse_mode=parse_mode
            )
            return
        try:
            self.telegram.edit_message_text(
                chat_id, message_id, text, reply_markup=reply_markup, parse_mode=parse_mode
            )
        except TelegramApiError as exc:
            error_text = str(exc).lower()
            if "message is not modified" in error_text:
                return
            if (
                "there is no text in the message to edit" in error_text
                or "message can't be edited" in error_text
                or "message to edit not found" in error_text
            ):
                logging.warning("Could not edit Telegram message; sending a new one: %s", exc)
                self.telegram.send_message(
                    chat_id, text, reply_markup=reply_markup, parse_mode=parse_mode
                )
                return
            raise

    def send_status(self, chat_id: int, page: int = 0, message_id: int | None = None) -> None:
        try:
            payload = self.panel.query_all()
            if payload.get("error"):
                self.send_or_edit(chat_id, message_id, f"查询失败：{payload.get('error')}")
                return
            zones = parse_zones(payload)
            page = clamp_page(page, len(zones))
            rows = pagination_rows("ip_page", page, len(zones))
            rows.append([{"text": "更换 IP", "callback_data": callback_data("cmd_change", "", "")}])
            if self.config.relay_sync_enabled:
                rows.append(
                    [
                        {
                            "text": "检查中转同步",
                            "callback_data": callback_data("relay_status", str(page), ""),
                        }
                    ]
                )
            keyboard = {"inline_keyboard": rows}
            reply_markup = keyboard if keyboard["inline_keyboard"] else None
            self.send_or_edit(
                chat_id,
                message_id,
                format_status_message(payload, zones, page),
                reply_markup=reply_markup,
            )
        except IppanelError as exc:
            self.send_or_edit(chat_id, message_id, f"面板请求失败：{exc}")
        except Exception as exc:
            logging.exception("Status command failed")
            self.send_or_edit(chat_id, message_id, f"查询出错：{exc}")

    def send_relay_status(
        self, chat_id: int, page: int = 0, message_id: int | None = None
    ) -> None:
        if not self.config.relay_sync_enabled:
            self.send_or_edit(chat_id, message_id, "中转同步未启用。请在 VPS 上运行 sudo boil config 开启。")
            return
        try:
            payload = self.panel.query_all()
            if payload.get("error"):
                self.send_or_edit(chat_id, message_id, f"查询失败：{payload.get('error')}")
                return
            zones = parse_zones(payload)
            if not zones:
                self.send_or_edit(chat_id, message_id, "没有从面板查到机器。")
                return
            page = clamp_page(page, len(zones))
            pages = total_pages(len(zones))
            lines = [tg_bold("中转同步绑定状态"), ""]
            if pages > 1:
                lines.append(f"第 {page + 1}/{pages} 页，共 {len(zones)} 台")
                lines.append("")

            start = page * PAGE_SIZE
            page_zones = zones[start : start + PAGE_SIZE]
            test_rows: list[list[dict[str, str]]] = []
            for offset, zone in enumerate(page_zones, start=1):
                index = start + offset
                lines.append(tg_bold(f"{index}. {zone.display_name}"))
                all_bindings = self.store.migrate_relay_bindings_for_zone(
                    zone.router_id,
                    zone.interface,
                    zone.display_name,
                    zone.dedicated_ip,
                    previous_ip=zone.current_ip,
                )
                matched = [
                    binding
                    for binding in all_bindings
                    if relay_binding_matches_zone(binding, zone)
                ]
                if matched:
                    lines.append(f"   绑定结果：已绑定 {len(matched)} 个")
                    for binding_index, binding in enumerate(matched, start=1):
                        lines.append(f"   绑定 {binding_index}")
                        lines.append(f"      目标名称：{binding.receiver_target_name}")
                        lines.append(f"      匹配模式：{relay_match_mode_label(binding.match_mode)}")
                        if binding_index < len(matched):
                            lines.append("")
                    if zone.current_ip:
                        test_rows.append(
                            [
                                {
                                    "text": f"测试同步：{short_text(zone.display_name, 24)}",
                                    "callback_data": callback_data(
                                        "relay_test", zone.router_id, zone.interface
                                    ),
                                }
                            ]
                        )
                    else:
                        lines.append("   测试同步：面板没有返回当前公网 IP")
                elif all_bindings:
                    lines.append("   绑定结果：绑定失效，机器标识不匹配")
                else:
                    lines.append("   绑定结果：未绑定")
                lines.append("")

            rows = pagination_rows("relay_page", page, len(zones))
            rows.extend(test_rows)
            rows.append([{"text": "更换 IP", "callback_data": callback_data("cmd_change", "", "")}])
            self.send_or_edit(
                chat_id,
                message_id,
                "\n".join(lines).strip(),
                reply_markup={"inline_keyboard": rows},
            )
        except IppanelError as exc:
            self.send_or_edit(chat_id, message_id, f"面板请求失败：{exc}")
        except Exception as exc:
            logging.exception("Relay status failed")
            self.send_or_edit(chat_id, message_id, f"检查中转同步失败：{exc}")

    def test_relay_sync(
        self,
        chat_id: int,
        router_id: str,
        interface: str,
        message_id: int | None = None,
    ) -> None:
        if not self.config.relay_sync_enabled:
            self.send_or_edit(chat_id, message_id, "中转同步未启用。请在 VPS 上运行 sudo boil config 开启。")
            return
        try:
            payload = self.panel.query_all(force=True)
            if payload.get("error"):
                self.send_or_edit(chat_id, message_id, f"查询失败：{payload.get('error')}")
                return
            zones = parse_zones(payload)
            zone = find_zone(zones, router_id, interface)
            if not zone:
                self.send_or_edit(chat_id, message_id, "面板里没有找到这台 VPS。")
                return
            zone_index = next(
                (
                    index
                    for index, item in enumerate(zones)
                    if item.router_id == str(router_id) and item.interface == str(interface)
                ),
                0,
            )
            return_page = zone_index // PAGE_SIZE

            bindings = self.store.migrate_relay_bindings_for_zone(
                router_id,
                interface,
                zone.display_name,
                zone.dedicated_ip,
                previous_ip=zone.current_ip,
            )
            matched = [
                binding for binding in bindings if relay_binding_matches_zone(binding, zone)
            ]
            lines = [tg_bold(f"{zone.display_name} 中转同步测试"), ""]
            if not bindings:
                lines.append("绑定结果：未绑定")
            elif not matched:
                lines.append("绑定结果：绑定失效，机器标识不匹配")
            elif not zone.current_ip:
                lines.append("测试结果：失败，面板没有返回当前公网 IP。")
            else:
                lines.append("测试方式：按每个绑定的匹配模式发送一次同步检测。")
                lines.append("")
                for index, binding in enumerate(matched, start=1):
                    old_ip = zone.current_ip if binding.match_mode in {"old_ip", "old_ip_unique"} else ""
                    try:
                        post_relay_report(binding, zone.current_ip, old_ip=old_ip)
                        self.store.update_relay_result(binding.id, zone.current_ip, "")
                        result = "成功"
                    except Exception as exc:
                        logging.exception("Relay sync test failed")
                        self.store.update_relay_result(binding.id, zone.current_ip, str(exc))
                        result = f"失败：{exc}"
                    lines.append(tg_bold(f"{index}. 目标名称：{binding.receiver_target_name}"))
                    lines.append(f"   匹配模式：{relay_match_mode_label(binding.match_mode)}")
                    lines.append(f"   结果：{result}")
                    if index < len(matched):
                        lines.append("")

            rows = [
                [
                    {
                        "text": "返回",
                        "callback_data": callback_data("relay_status", str(return_page), ""),
                    },
                    {"text": "更换 IP", "callback_data": callback_data("cmd_change", "", "")},
                ]
            ]
            self.send_or_edit(
                chat_id,
                message_id,
                "\n".join(lines).strip(),
                reply_markup={"inline_keyboard": rows},
            )
        except IppanelError as exc:
            self.send_or_edit(chat_id, message_id, f"面板请求失败：{exc}")
        except Exception as exc:
            logging.exception("Relay sync test command failed")
            self.send_or_edit(chat_id, message_id, f"测试中转同步失败：{exc}")

    def send_change_menu(self, chat_id: int, page: int = 0, message_id: int | None = None) -> None:
        self.pending_inputs.pop(chat_id, None)
        try:
            payload = self.panel.query_all()
            if payload.get("error"):
                self.send_or_edit(chat_id, message_id, f"查询失败：{payload.get('error')}")
                return
            zones = parse_zones(payload)
            operable = [zone for zone in zones if zone.operable]
            if not operable:
                self.send_or_edit(chat_id, message_id, "没有可更换的机器。")
                return

            lines = ["选择要更换 IP 的机器", quota_text(payload), ""]
            page = clamp_page(page, len(operable))
            pages = total_pages(len(operable))
            if pages > 1:
                lines.append(f"第 {page + 1}/{pages} 页，共 {len(operable)} 台可更换")
                lines.append("")

            start = page * PAGE_SIZE
            page_zones = operable[start : start + PAGE_SIZE]
            for offset, zone in enumerate(page_zones, start=1):
                index = start + offset
                lines.extend(format_zone_line(index, zone))
                lines.append("")

            rows = []
            for offset, zone in enumerate(page_zones, start=1):
                index = start + offset
                label_parts = [f"{index}. 换 {zone.display_name}"]
                if zone.current_ip:
                    label_parts.append(zone.current_ip)
                rows.append(
                    [
                        {
                            "text": short_text(" ".join(label_parts), 60),
                            "callback_data": callback_data(
                                "pick", zone.router_id, zone.interface
                            ),
                        }
                    ]
                )
            rows.extend(pagination_rows("change_page", page, len(operable)))
            keyboard = {
                "inline_keyboard": rows
            }
            self.send_or_edit(chat_id, message_id, "\n".join(lines).strip(), reply_markup=keyboard)
        except IppanelError as exc:
            self.send_or_edit(chat_id, message_id, f"面板请求失败：{exc}")
        except Exception as exc:
            logging.exception("Change menu failed")
            self.send_or_edit(chat_id, message_id, f"生成更换菜单失败：{exc}")

    def query_zone_for_action(self, router_id: str, interface: str) -> ZoneItem | None:
        payload = self.panel.query_all()
        zones = parse_zones(payload)
        return find_zone(zones, router_id, interface)

    def show_change_modes(self, chat_id: int, message_id: int, router_id: str, interface: str) -> None:
        try:
            zone = self.query_zone_for_action(router_id, interface)
            if not zone:
                self.telegram.edit_message_text(
                    chat_id, message_id, "面板里没有找到这台机器，请重新发送 /change。"
                )
                return
            if not zone.operable:
                self.telegram.edit_message_text(
                    chat_id,
                    message_id,
                    f"{zone.display_name} 当前不可更换：{status_label(zone)}",
                )
                return

            lines = ["选择更换方式", ""]
            lines.extend(format_zone_line(1, zone))
            keyboard = {
                "inline_keyboard": [
                    [
                        {
                            "text": "立即更换",
                            "callback_data": callback_data(
                                "now", zone.router_id, zone.interface
                            ),
                        }
                    ],
                    [
                        {
                            "text": "延时更换",
                            "callback_data": callback_data(
                                "delay", zone.router_id, zone.interface
                            ),
                        },
                        {
                            "text": "计划任务",
                            "callback_data": callback_data(
                                "plan", zone.router_id, zone.interface
                            ),
                        },
                    ],
                    [
                        {
                            "text": "取消",
                            "callback_data": callback_data(
                                "cancel", zone.router_id, zone.interface
                            ),
                        }
                    ],
                ]
            }
            self.telegram.edit_message_text(
                chat_id,
                message_id,
                telegram_html("\n".join(lines)),
                reply_markup=keyboard,
                parse_mode="HTML",
            )
        except IppanelError as exc:
            self.telegram.edit_message_text(chat_id, message_id, f"面板请求失败：{exc}")

    def ask_delay_seconds(
        self, chat_id: int, message_id: int, router_id: str, interface: str
    ) -> None:
        try:
            zone = self.query_zone_for_action(router_id, interface)
            if not zone or not zone.operable:
                self.telegram.edit_message_text(
                    chat_id, message_id, "这台机器当前不可更换，请重新发送 /change。"
                )
                return
            self.pending_inputs[chat_id] = {
                "mode": "delay",
                "router_id": zone.router_id,
                "interface": zone.interface,
                "target_name": zone.display_name,
            }
            lines = [
                f"请输入延时秒数：10-600",
                f"目标：{zone.display_name}",
                "",
                "例如：60",
                "取消输入：/cancel",
            ]
            self.telegram.edit_message_text(chat_id, message_id, "\n".join(lines))
        except IppanelError as exc:
            self.telegram.edit_message_text(chat_id, message_id, f"面板请求失败：{exc}")

    def show_plan_type_menu(
        self, chat_id: int, message_id: int, router_id: str, interface: str
    ) -> None:
        try:
            zone = self.query_zone_for_action(router_id, interface)
            if not zone or not zone.operable:
                self.telegram.edit_message_text(
                    chat_id, message_id, "这台机器当前不可更换，请重新发送 /change。"
                )
                return
            now_text = format_run_time(int(time.time()), self.timezone, self.config.timezone_name)
            lines = [
                "选择计划任务类型",
                f"目标：{zone.display_name}",
                f"当前时区：{self.config.timezone_name}",
                f"当前时间：{now_text}",
            ]
            keyboard = {
                "inline_keyboard": [
                    [
                        {
                            "text": "自定义日期",
                            "callback_data": callback_data(
                                "plan_once", zone.router_id, zone.interface
                            ),
                        }
                    ],
                    [
                        {
                            "text": "每 X 天",
                            "callback_data": callback_data(
                                "plan_days", zone.router_id, zone.interface
                            ),
                        },
                        {
                            "text": "每周",
                            "callback_data": callback_data(
                                "plan_weekly", zone.router_id, zone.interface
                            ),
                        },
                    ],
                    [
                        {
                            "text": "每月",
                            "callback_data": callback_data(
                                "plan_monthly", zone.router_id, zone.interface
                            ),
                        },
                        {
                            "text": "取消",
                            "callback_data": callback_data(
                                "cancel", zone.router_id, zone.interface
                            ),
                        },
                    ],
                ]
            }
            self.telegram.edit_message_text(
                chat_id,
                message_id,
                telegram_html("\n".join(lines)),
                reply_markup=keyboard,
                parse_mode="HTML",
            )
        except IppanelError as exc:
            self.telegram.edit_message_text(chat_id, message_id, f"面板请求失败：{exc}")

    def ask_plan_input(
        self,
        chat_id: int,
        message_id: int,
        router_id: str,
        interface: str,
        mode: str,
    ) -> None:
        try:
            zone = self.query_zone_for_action(router_id, interface)
            if not zone or not zone.operable:
                self.telegram.edit_message_text(
                    chat_id, message_id, "这台机器当前不可更换，请重新发送 /change。"
                )
                return
            self.pending_inputs[chat_id] = {
                "mode": mode,
                "router_id": zone.router_id,
                "interface": zone.interface,
                "target_name": zone.display_name,
            }
            base_lines = [
                f"目标：{zone.display_name}",
                f"当前时区：{self.config.timezone_name}",
                "取消输入：/cancel",
                "",
            ]
            example_dt = datetime.now(self.timezone) + timedelta(hours=1)
            if mode == "once":
                lines = [
                    "请输入自定义执行日期和时间。",
                    *base_lines,
                    "格式：YYYY-MM-DD HH:MM",
                    f"例如：{example_dt:%Y-%m-%d %H:%M}",
                ]
            elif mode == "every_days":
                lines = [
                    "请输入每 X 天执行的间隔和时间。",
                    *base_lines,
                    "格式：天数 HH:MM",
                    "例如：3 23:30",
                ]
            elif mode == "weekly":
                lines = [
                    "请输入每周执行的星期和时间。",
                    *base_lines,
                    "格式：星期 HH:MM",
                    "星期用 1-7 表示，1=周一，7=周日",
                    "例如：5 23:30",
                ]
            elif mode == "monthly":
                lines = [
                    "请输入每月执行的日期和时间。",
                    *base_lines,
                    "格式：日期 HH:MM",
                    "日期用 1-31；如果某月没有这一天，会使用当月最后一天",
                    "例如：15 23:30",
                ]
            else:
                self.pending_inputs.pop(chat_id, None)
                self.telegram.edit_message_text(chat_id, message_id, "计划类型无效，请重新发送 /change。")
                return
            self.telegram.edit_message_text(chat_id, message_id, "\n".join(lines))
        except IppanelError as exc:
            self.telegram.edit_message_text(chat_id, message_id, f"面板请求失败：{exc}")

    def show_confirm(self, chat_id: int, message_id: int, router_id: str, interface: str) -> None:
        try:
            payload = self.panel.query_all()
            zones = parse_zones(payload)
            zone = find_zone(zones, router_id, interface)
            if not zone:
                self.telegram.edit_message_text(
                    chat_id, message_id, "面板里没有找到这台机器，请重新发送 /change。"
                )
                return
            if not zone.operable:
                self.telegram.edit_message_text(
                    chat_id,
                    message_id,
                    f"{zone.display_name} 当前不可更换：{status_label(zone)}",
                )
                return

            lines = ["确认更换这台机器的 IP？", ""]
            lines.extend(format_zone_line(1, zone))
            keyboard = {
                "inline_keyboard": [
                    [
                        {
                            "text": "确认更换",
                            "callback_data": callback_data(
                                "confirm", zone.router_id, zone.interface
                            ),
                        },
                        {
                            "text": "取消",
                            "callback_data": callback_data(
                                "cancel", zone.router_id, zone.interface
                            ),
                        },
                    ]
                ]
            }
            self.telegram.edit_message_text(
                chat_id,
                message_id,
                telegram_html("\n".join(lines)),
                reply_markup=keyboard,
                parse_mode="HTML",
            )
        except IppanelError as exc:
            self.telegram.edit_message_text(chat_id, message_id, f"面板请求失败：{exc}")

    def begin_api_change(
        self,
        chat_id: int,
        message_id: int,
        router_id: str,
        interface: str,
        scheduled_job_id: int | None = None,
    ) -> str:
        if not isinstance(self.panel, IppanelApiClient):
            raise IppanelError("当前不是 API 模式。")
        if self.store.active_api_change(router_id, interface):
            raise IppanelError("这台机器已有正在确认的新 IP，请勿重复提交。")
        next_allowed_at = self.store.latest_api_cooldown(router_id, interface)
        if next_allowed_at and next_allowed_at > int(time.time()):
            raise IppanelError(
                "仍在换 IP CD，下一次允许时间："
                f"{format_run_time(next_allowed_at, self.timezone, self.config.timezone_name)}"
            )

        old_ip = self.panel.get_target_ip(router_id, interface)
        target_name = self.panel.target_label(router_id, interface)
        now = int(time.time())
        operation_id = self.store.add_api_change_operation(
            chat_id=chat_id,
            message_id=message_id,
            router_id=router_id,
            interface=interface,
            target_name=target_name,
            old_ip=old_ip,
            requested_at=now,
            next_check_at=now + self.config.api_change_initial_delay_seconds,
            confirm_deadline=now + self.config.api_change_confirm_timeout_seconds,
            scheduled_job_id=scheduled_job_id,
        )

        try:
            response = self.panel.reconnect(router_id, interface)
        except IppanelTransientError as exc:
            logging.warning(
                "API change response was inconclusive for %s/%s: %s",
                router_id,
                interface,
                exc,
            )
            self.store.accept_api_change_operation(operation_id, None, None, str(exc))
            return "\n".join(
                [
                    tg_bold(f"{target_name} 换 IP 请求结果暂不明确"),
                    f"旧 IP：{old_ip}",
                    f"API 返回：{exc}",
                    "",
                    "Bot 将只查询 IP 来确认结果，不会重复提交换 IP。",
                ]
            )
        except Exception as exc:
            self.store.finish_api_change(operation_id, "request_failed", error=str(exc))
            raise

        uses_left = optional_int(response.get("uses_left"))
        next_allowed_at = optional_int(response.get("next_allowed_at"))
        self.store.accept_api_change_operation(
            operation_id, uses_left, next_allowed_at
        )
        return format_api_change_accepted(
            target_name,
            old_ip,
            uses_left,
            next_allowed_at,
            self.timezone,
            self.config.timezone_name,
        )

    def run_change(
        self,
        router_id: str,
        interface: str,
        progress_callback: Callable[[str], None] | None = None,
    ) -> str:
        key = (str(router_id), str(interface))
        if key in self.changing:
            raise IppanelError("这台机器已经在更换中，请稍等。")

        self.changing.add(key)
        payload_before: dict[str, Any] | None = None
        zone_before: ZoneItem | None = None
        try:
            payload_before = self.panel.query_all()
            zone_before = find_zone(parse_zones(payload_before), router_id, interface)
            target_name = zone_before.display_name if zone_before else "目标机器"
            reconnect_data: dict[str, Any] = {}
            attempts_used = 0
            for attempt in range(1, self.config.change_max_attempts + 1):
                attempts_used = attempt
                if progress_callback:
                    progress_callback(
                        f"正在更换 {target_name} 的 IP，第 {attempt}/{self.config.change_max_attempts} 次尝试…"
                    )
                reconnect_data = self.panel.reconnect(router_id, interface)
                if not should_retry_change_result(reconnect_data):
                    break
                if attempt >= self.config.change_max_attempts:
                    break
                reason = change_retry_reason(reconnect_data)
                if progress_callback:
                    progress_callback(
                        f"第 {attempt} 次更换未成功：{reason}\n"
                        f"{self.config.change_retry_delay_seconds} 秒后自动重试。"
                    )
                time.sleep(self.config.change_retry_delay_seconds)

            payload_after: dict[str, Any] | None = None
            zone_after: ZoneItem | None = None
            if self.config.post_change_query_delay_seconds:
                time.sleep(self.config.post_change_query_delay_seconds)
            try:
                payload_after = self.panel.query_all()
                zone_after = find_zone(parse_zones(payload_after), router_id, interface)
            except IppanelError:
                logging.exception("Post-change query failed")

            result = format_change_result(zone_before, reconnect_data, payload_after, zone_after)
            self.last_change_context[key] = ChangeContext(
                zone_before=zone_before,
                reconnect_data=dict(reconnect_data),
                payload_after=payload_after,
                zone_after=zone_after,
            )
            if attempts_used > 1:
                result += f"\n尝试次数：{attempts_used}/{self.config.change_max_attempts}"
            return result
        finally:
            self.changing.discard(key)

    def perform_change(self, chat_id: int, message_id: int, router_id: str, interface: str) -> None:
        try:
            if self.config.ippanel_mode == "api":
                self.telegram.edit_message_text(
                    chat_id, message_id, "正在查询旧 IP 并提交一次换 IP 请求…"
                )
                result = self.begin_api_change(
                    chat_id, message_id, router_id, interface
                )
                self.telegram.edit_message_text(
                    chat_id, message_id, telegram_html(result), parse_mode="HTML"
                )
                return

            def progress(text: str) -> None:
                self.telegram.edit_message_text(chat_id, message_id, text)

            progress("正在更换 IP，请稍候…")
            result = self.run_change(router_id, interface, progress)
            ddns_result = self.sync_ddns_after_change(chat_id, router_id, interface)
            if ddns_result:
                result = f"{result}\n\n{ddns_result}"
            relay_result = self.sync_relay_after_change(router_id, interface)
            if relay_result:
                result = f"{result}\n\n{relay_result}"
            self.telegram.edit_message_text(
                chat_id, message_id, telegram_html(result), parse_mode="HTML"
            )
        except IppanelError as exc:
            self.telegram.edit_message_text(
                chat_id, message_id, telegram_html(f"更换失败：{exc}"), parse_mode="HTML"
            )
        except Exception as exc:
            logging.exception("Change failed")
            self.telegram.edit_message_text(
                chat_id, message_id, telegram_html(f"更换出错：{exc}"), parse_mode="HTML"
            )

    def sync_ddns_after_change(self, chat_id: int, router_id: str, interface: str) -> str:
        if not (self.config.ddns_enabled and self.config.ddns_sync_after_change):
            return ""
        context = self.last_change_context.get((str(router_id), str(interface)))
        reconnect_data = context.reconnect_data if context else {}
        if reconnect_data.get("error") or reconnect_data.get("ip_pending"):
            return ""
        target_name = context.zone_after.display_name if context and context.zone_after else ""
        if not target_name and context and context.zone_before:
            target_name = context.zone_before.display_name
        previous_ip = context.zone_before.current_ip if context and context.zone_before else ""
        binding = self.store.get_ddns_binding_for_zone(
            chat_id,
            router_id,
            interface,
            target_name=target_name,
            previous_ip=previous_ip,
        )
        if not binding:
            return ""
        try:
            return self.sync_ddns_binding_with_current_ip(binding)
        except Exception as exc:
            logging.exception("DDNS sync after change failed")
            return f"DDNS 同步失败：{exc}"

    def sync_ddns_after_confirmed(
        self,
        chat_id: int,
        router_id: str,
        interface: str,
        new_ip: str,
        target_name: str = "",
        previous_ip: str = "",
    ) -> str:
        if not (self.config.ddns_enabled and self.config.ddns_sync_after_change):
            return ""
        binding = self.store.get_ddns_binding_for_zone(
            chat_id,
            router_id,
            interface,
            target_name=target_name,
            previous_ip=previous_ip,
        )
        if not binding:
            return ""
        try:
            return self.sync_ddns_binding(binding, new_ip)
        except Exception as exc:
            logging.exception("DDNS sync after API change failed")
            return f"DDNS 同步失败：{exc}"

    def sync_relay_after_change(self, router_id: str, interface: str) -> str:
        if not (self.config.relay_sync_enabled and self.config.relay_sync_after_change):
            return ""
        key = (str(router_id), str(interface))
        context = self.last_change_context.get(key)
        reconnect_data = context.reconnect_data if context else {}
        if (
            reconnect_data.get("error")
            or reconnect_data.get("ip_pending")
            or reconnect_data.get("ip_unchanged")
        ):
            return ""

        zone = context.zone_after if context else None
        if not zone:
            try:
                payload = self.panel.query_all(force=True)
                zone = find_zone(parse_zones(payload), router_id, interface)
            except Exception as exc:
                logging.exception("Relay sync post-change query failed")
                return f"中转同步失败：无法确认当前 VPS 状态：{exc}"
        if not zone:
            return "中转同步失败：面板里没有找到已绑定的 VPS。"
        if not zone.dedicated_ip and zone.interface != API_INTERFACE:
            return "中转同步失败：面板没有返回内网 IP，无法校验绑定。"

        bindings = self.store.migrate_relay_bindings_for_zone(
            router_id,
            interface,
            zone.display_name,
            zone.dedicated_ip,
            previous_ip=str(
                reconnect_data.get("old_ip")
                or (context.zone_before.current_ip if context and context.zone_before else "")
                or zone.current_ip
            ).strip(),
        )
        if not bindings:
            return ""

        matched = [
            binding for binding in bindings if relay_binding_matches_zone(binding, zone)
        ]
        if not matched:
            return "中转同步跳过：机器标识不匹配，请在 VPS 上重新运行 sudo boil relay。"

        new_ip = (
            str(reconnect_data.get("new_ip") or "").strip()
            or zone.current_ip
        )
        old_ip = (
            str(reconnect_data.get("old_ip") or "").strip()
            or (context.zone_before.current_ip if context and context.zone_before else "")
        )
        if not new_ip:
            return "中转同步失败：面板没有返回当前公网 IP。"

        lines = [tg_bold("中转同步结果")]
        for index, binding in enumerate(matched, start=1):
            try:
                post_relay_report(binding, new_ip, old_ip=old_ip)
                self.store.update_relay_result(binding.id, new_ip, "")
                result = "已更新转发目标"
            except Exception as exc:
                logging.exception("Relay sync failed")
                self.store.update_relay_result(binding.id, new_ip, str(exc))
                result = f"失败：{exc}"
            lines.append(tg_bold(f"{index}. 目标名称：{binding.receiver_target_name}"))
            lines.append(f"   匹配模式：{relay_match_mode_label(binding.match_mode)}")
            lines.append(f"   结果：{result}")
            if index < len(matched):
                lines.append("")
        return "\n".join(lines)

    def sync_ddns_binding_with_current_ip(self, binding: DdnsBinding) -> str:
        error = self.ddns_config_error()
        if error:
            raise DdnsError(error)
        payload = self.panel.query_all(force=True)
        zone = find_zone(parse_zones(payload), binding.router_id, binding.interface)
        if not zone:
            raise DdnsError("面板里没有找到 DDNS 绑定的 VPS。")
        if not zone.current_ip:
            raise DdnsError("面板没有返回当前公网 IP。")
        return self.sync_ddns_binding(binding, zone.current_ip)

    def sync_ddns_binding(self, binding: DdnsBinding, ip: str) -> str:
        if not self.cloudflare:
            raise DdnsError("Cloudflare 未配置。")
        hostname = validate_hostname(binding.hostname)
        record_id = binding.record_id
        ttl = self.config.ddns_ttl_seconds
        proxied = binding.proxied
        if not record_id:
            record = self.cloudflare.find_a_record(hostname)
            if record:
                record_id = str(record.get("id") or "")
                ttl = self.config.ddns_ttl_seconds
                proxied = bool(record.get("proxied", proxied))
            else:
                ttl = self.config.ddns_ttl_seconds
                record = self.cloudflare.create_a_record(hostname, ip, ttl)
                record_id = str(record.get("id") or "")
                ttl = parse_int(record.get("ttl"), ttl)
                proxied = bool(record.get("proxied", proxied))
                self.store.update_ddns_result(binding.id, record_id, ip, ttl, proxied)
                return f"DDNS 已创建并同步：{hostname} -> {ip}"

        try:
            record = self.cloudflare.update_a_record(record_id, hostname, ip, ttl, proxied)
        except DdnsError:
            record = self.cloudflare.find_a_record(hostname)
            if not record:
                raise
            record_id = str(record.get("id") or "")
            ttl = self.config.ddns_ttl_seconds
            proxied = bool(record.get("proxied", proxied))
            record = self.cloudflare.update_a_record(record_id, hostname, ip, ttl, proxied)
        record_id = str(record.get("id") or record_id)
        ttl = parse_int(record.get("ttl"), ttl)
        proxied = bool(record.get("proxied", proxied))
        self.store.update_ddns_result(binding.id, record_id, ip, ttl, proxied)
        return f"DDNS 已同步：{hostname} -> {ip}"

    def handle_ddns_hostname_input(self, chat_id: int, text: str, state: dict[str, str]) -> None:
        error = self.ddns_config_error()
        if error:
            self.pending_inputs.pop(chat_id, None)
            self.telegram.send_message(chat_id, error)
            return
        router_id = state.get("router_id", "")
        interface = state.get("interface", "")
        target_name = state.get("target_name", "目标机器")
        try:
            hostname = validate_hostname(text)
            zone = self.query_zone_for_action(router_id, interface)
            if not zone:
                raise DdnsError("面板里没有找到这台 VPS。")
            if not zone.current_ip:
                raise DdnsError("面板没有返回当前公网 IP，无法创建或同步记录。")
            binding_id = self.store.upsert_ddns_binding(
                chat_id,
                router_id,
                interface,
                target_name,
                hostname,
                last_ip=zone.current_ip,
            )
            binding = self.store.get_ddns_binding(chat_id, router_id, interface)
            if not binding:
                raise DdnsError("保存 DDNS 绑定失败。")
            binding.id = binding_id
            result = self.sync_ddns_binding(binding, zone.current_ip)
            self.pending_inputs.pop(chat_id, None)
            message = "\n".join(
                [
                    "DDNS 绑定已保存",
                    f"目标：{target_name}",
                    f"域名：{hostname}",
                    result,
                ]
            )
            self.telegram.send_message(
                chat_id,
                telegram_html(message),
                parse_mode="HTML",
            )
        except ValueError:
            self.telegram.send_message(
                chat_id,
                telegram_html("hostname 格式不正确，请重新输入，例如 hk1.example.com，或发送 /cancel。"),
                parse_mode="HTML",
            )
        except Exception as exc:
            logging.exception("DDNS hostname input failed")
            self.telegram.send_message(chat_id, f"DDNS 配置失败：{exc}")

    def sync_all_ddns(self, chat_id: int, message_id: int | None = None) -> None:
        error = self.ddns_config_error()
        if error:
            self.send_or_edit(chat_id, message_id, error)
            return
        bindings = self.store.list_ddns_bindings(chat_id)
        if not bindings:
            self.send_or_edit(chat_id, message_id, "当前没有 DDNS 绑定。")
            return
        lines = ["DDNS 手动同步结果"]
        for index, binding in enumerate(bindings, start=1):
            try:
                result = self.sync_ddns_binding_with_current_ip(binding)
                lines.append(f"{index}. {result}")
            except Exception as exc:
                logging.exception("Manual DDNS sync failed")
                lines.append(f"{index}. {binding.hostname} 同步失败：{exc}")
        self.send_or_edit(chat_id, message_id, "\n".join(lines))

    def handle_schedule_input(self, chat_id: int, text: str) -> None:
        state = self.pending_inputs.get(chat_id)
        if not state:
            return

        mode = state.get("mode", "")
        if mode == "ddns_hostname":
            self.handle_ddns_hostname_input(chat_id, text, state)
            return
        router_id = state.get("router_id", "")
        interface = state.get("interface", "")
        target_name = state.get("target_name", "目标机器")

        try:
            now_dt = datetime.now(self.timezone)
            schedule_type = "once"
            interval_days = 0
            weekday = 0
            month_day = 0
            time_of_day = ""
            description = "一次性任务"

            if mode == "delay":
                seconds = parse_int(text, -1)
                if not (10 <= seconds <= 600):
                    self.telegram.send_message(chat_id, "延时秒数必须是 10-600。请重新输入，或发送 /cancel。")
                    return
                run_at = int(time.time()) + seconds
            elif mode == "once":
                run_at_dt = parse_custom_datetime(text, now_dt)
                if run_at_dt <= now_dt:
                    self.telegram.send_message(
                        chat_id,
                        "这个时间已经过去了，请输入未来时间。\n"
                        f"当前时间：{format_run_time(int(now_dt.timestamp()), self.timezone, self.config.timezone_name)}\n"
                        "取消输入：/cancel",
                    )
                    return
                run_at = int(run_at_dt.timestamp())
            elif mode == "every_days":
                parts = text.split()
                if len(parts) != 2:
                    raise ValueError("bad every_days input")
                interval_days = parse_int(parts[0], -1)
                if not (1 <= interval_days <= 365):
                    self.telegram.send_message(chat_id, "天数必须是 1-365。请重新输入，或发送 /cancel。")
                    return
                time_of_day, _, _ = parse_time_of_day(parts[1])
                schedule_type = "every_days"
                run_at = first_every_days_run_at(now_dt, interval_days, time_of_day)
                description = f"每 {interval_days} 天 {time_of_day}"
            elif mode == "weekly":
                parts = text.split()
                if len(parts) != 2:
                    raise ValueError("bad weekly input")
                weekday = parse_int(parts[0], -1)
                if not (1 <= weekday <= 7):
                    self.telegram.send_message(chat_id, "星期必须是 1-7，1=周一，7=周日。请重新输入，或发送 /cancel。")
                    return
                time_of_day, _, _ = parse_time_of_day(parts[1])
                schedule_type = "weekly"
                run_at = first_weekly_run_at(now_dt, weekday, time_of_day)
                description = f"每周{WEEKDAY_NAMES.get(weekday, weekday)} {time_of_day}"
            elif mode == "monthly":
                parts = text.split()
                if len(parts) != 2:
                    raise ValueError("bad monthly input")
                month_day = parse_int(parts[0], -1)
                if not (1 <= month_day <= 31):
                    self.telegram.send_message(chat_id, "日期必须是 1-31。请重新输入，或发送 /cancel。")
                    return
                time_of_day, _, _ = parse_time_of_day(parts[1])
                schedule_type = "monthly"
                run_at = first_monthly_run_at(now_dt, month_day, time_of_day)
                description = f"每月 {month_day} 日 {time_of_day}"
            else:
                self.pending_inputs.pop(chat_id, None)
                self.telegram.send_message(chat_id, "当前输入状态无效，请重新发送 /change。")
                return

            job_id = self.store.add_scheduled_change(
                chat_id=chat_id,
                router_id=router_id,
                interface=interface,
                target_name=target_name,
                run_at=run_at,
                schedule_type=schedule_type,
                interval_days=interval_days,
                weekday=weekday,
                month_day=month_day,
                time_of_day=time_of_day,
                timezone_name=self.config.timezone_name,
            )
            display_number = self.pending_job_number(chat_id, job_id)
            self.pending_inputs.pop(chat_id, None)
            run_label = "首次执行" if is_recurring_schedule(schedule_type) else "执行时间"
            self.telegram.send_message(
                chat_id,
                "\n".join(
                    [
                        f"已安排任务 {display_number}",
                        f"目标：{target_name}",
                        f"计划：{description}",
                        f"{run_label}：{format_run_time(run_at, self.timezone, self.config.timezone_name)}",
                        "",
                        f"取消任务：/canceljob {display_number}",
                        "查看任务：/jobs",
                    ]
                ),
            )
        except ValueError:
            self.telegram.send_message(
                chat_id,
                "输入格式不对。请按提示重新输入，或发送 /cancel。",
            )
        except Exception as exc:
            logging.exception("Schedule input failed")
            self.telegram.send_message(chat_id, f"创建计划任务失败：{exc}")

    def pending_job_number(self, chat_id: int, job_id: int) -> int:
        for index, job in enumerate(self.store.list_scheduled_changes(chat_id), start=1):
            if job.id == job_id:
                return index
        return 1

    def send_jobs(self, chat_id: int) -> None:
        jobs = self.store.list_scheduled_changes(chat_id)
        if not jobs:
            self.telegram.send_message(chat_id, "当前没有未执行的延时/计划任务。")
            return
        lines = ["未执行任务"]
        for index, job in enumerate(jobs, start=1):
            job_tz_name = job.timezone_name or self.config.timezone_name
            job_tz = load_timezone(job_tz_name)
            target_name = safe_target_name(job.target_name, job.router_id, job.interface)
            lines.append("")
            lines.append(f"{index}. {target_name}")
            lines.append(f"计划：{schedule_description(job)}")
            lines.append(f"下次执行：{format_run_time(job.run_at, job_tz, job_tz_name)}")
            lines.append(f"取消：/canceljob {index}")
        self.telegram.send_message(chat_id, "\n".join(lines))

    def handle_cancel_job(self, chat_id: int, text: str) -> None:
        parts = text.split(maxsplit=1)
        if len(parts) != 2:
            self.telegram.send_message(chat_id, "用法：/canceljob 1")
            return
        display_number = parse_int(parts[1], -1)
        jobs = self.store.list_scheduled_changes(chat_id)
        if display_number <= 0 or display_number > len(jobs):
            self.telegram.send_message(chat_id, "任务序号不正确，请先用 /jobs 查看当前任务列表。")
            return
        job = jobs[display_number - 1]
        if self.store.cancel_scheduled_change(job.id, chat_id):
            self.telegram.send_message(chat_id, f"已取消任务 {display_number}。")
        else:
            self.telegram.send_message(chat_id, f"没有找到可取消的任务 {display_number}。")

    def handle_ddns_delete(self, chat_id: int, text: str) -> None:
        error = self.ddns_config_error()
        if error:
            self.telegram.send_message(chat_id, error)
            return
        parts = text.split(maxsplit=1)
        if len(parts) != 2:
            self.telegram.send_message(chat_id, "用法：/ddnsdel 1")
            return
        display_number = parse_int(parts[1], -1)
        bindings = self.store.list_ddns_bindings(chat_id)
        if display_number <= 0 or display_number > len(bindings):
            self.telegram.send_message(chat_id, "DDNS 绑定序号不正确，请先打开 DDNS 绑定列表。")
            return
        binding = bindings[display_number - 1]
        if self.store.delete_ddns_binding(binding.id, chat_id):
            self.telegram.send_message(chat_id, f"已删除 DDNS 绑定 {display_number}：{binding.hostname}")
        else:
            self.telegram.send_message(chat_id, f"没有找到可删除的 DDNS 绑定 {display_number}。")

    def finish_api_scheduled_job(
        self, operation: ApiChangeOperation, result: str, succeeded: bool
    ) -> None:
        if operation.scheduled_job_id is None:
            return
        job = self.store.get_scheduled_change(operation.scheduled_job_id)
        if not job:
            logging.warning(
                "API confirmation references missing scheduled job %s",
                operation.scheduled_job_id,
            )
            return

        next_run_at = next_recurring_run_at(job, int(time.time()))
        error = "" if succeeded else operation.last_error or result
        if next_run_at:
            self.store.reschedule_scheduled_change(job.id, next_run_at, error)
            job_tz_name = job.timezone_name or self.config.timezone_name
            job_tz = load_timezone(job_tz_name)
            result = (
                f"{result}\n\n"
                f"下次执行：{format_run_time(next_run_at, job_tz, job_tz_name)}"
            )
        else:
            self.store.finish_scheduled_change(
                job.id, "done" if succeeded else "failed", error
            )
        self.telegram.send_message(
            operation.chat_id,
            telegram_html(f"计划任务\n{result}"),
            parse_mode="HTML",
        )

    def notify_api_change(self, operation: ApiChangeOperation, result: str) -> None:
        if operation.scheduled_job_id is not None:
            return
        self.send_or_edit(
            operation.chat_id,
            operation.message_id or None,
            result,
        )

    def complete_api_change(self, operation: ApiChangeOperation, new_ip: str) -> None:
        self.store.finish_api_change(operation.id, "confirmed", new_ip=new_ip)
        if self.api_panel:
            self.api_panel.invalidate_cache()
        zone_before = ZoneItem(
            router_id=operation.router_id,
            interface=operation.interface,
            label=operation.target_name,
            dedicated_ip="",
            current_ip=operation.old_ip,
            status="ok",
            status_msg="",
        )
        zone_after = ZoneItem(
            router_id=operation.router_id,
            interface=operation.interface,
            label=operation.target_name,
            dedicated_ip="",
            current_ip=new_ip,
            status="ok",
            status_msg="",
        )
        key = (operation.router_id, operation.interface)
        self.last_change_context[key] = ChangeContext(
            zone_before=zone_before,
            reconnect_data={"old_ip": operation.old_ip, "new_ip": new_ip},
            payload_after=None,
            zone_after=zone_after,
        )

        result = format_api_change_confirmed(
            operation, new_ip, self.timezone, self.config.timezone_name
        )
        ddns_result = self.sync_ddns_after_confirmed(
            operation.chat_id,
            operation.router_id,
            operation.interface,
            new_ip,
            target_name=operation.target_name,
            previous_ip=operation.old_ip,
        )
        if ddns_result:
            result = f"{result}\n\n{ddns_result}"
        relay_result = self.sync_relay_after_change(
            operation.router_id, operation.interface
        )
        if relay_result:
            result = f"{result}\n\n{relay_result}"

        self.notify_api_change(operation, result)
        self.finish_api_scheduled_job(operation, result, True)

    def timeout_api_change(self, operation: ApiChangeOperation, error: str) -> None:
        self.store.finish_api_change(
            operation.id, "confirmation_timeout", error=error
        )
        operation.last_error = error
        result = "\n".join(
            [
                tg_bold(f"{operation.target_name} 换 IP 暂时无法确认"),
                f"换 IP 前：{operation.old_ip}",
                f"最近查询：{error}",
                "",
                "Bot 没有重复提交换 IP。请稍后使用 /ip 查询。",
            ]
        )
        self.notify_api_change(operation, result)
        self.finish_api_scheduled_job(operation, result, False)

    def run_due_api_change_confirmations(self) -> None:
        operations = self.store.due_api_changes(int(time.time()), limit=5)
        for operation in operations:
            try:
                if not self.api_panel:
                    error = "API targets 配置不可用，无法继续确认。"
                    if int(time.time()) >= operation.confirm_deadline:
                        self.timeout_api_change(operation, error)
                    else:
                        next_check = (
                            int(time.time())
                            + self.config.api_change_poll_interval_seconds
                        )
                        self.store.reschedule_api_change(
                            operation.id,
                            next_check,
                            operation.check_count + 1,
                            error,
                        )
                    continue

                try:
                    current_ip = self.api_panel.get_target_ip(
                        operation.router_id, operation.interface
                    )
                    error = ""
                except IppanelError as exc:
                    current_ip = ""
                    error = str(exc)

                now = int(time.time())
                if current_ip and current_ip != operation.old_ip:
                    self.complete_api_change(operation, current_ip)
                    continue

                if not error:
                    error = f"当前仍为旧 IP：{operation.old_ip}"
                if now >= operation.confirm_deadline:
                    self.timeout_api_change(operation, error)
                    continue

                check_count = operation.check_count + 1
                delay = api_confirmation_delay(
                    check_count, self.config.api_change_poll_interval_seconds
                )
                self.store.reschedule_api_change(
                    operation.id, now + delay, check_count, error
                )
            except TelegramError as exc:
                logging.warning(
                    "Could not notify API change operation %s: %s", operation.id, exc
                )
            except Exception:
                logging.exception(
                    "API change confirmation failed for operation %s", operation.id
                )

    def run_due_scheduled_changes(self) -> None:
        due_jobs = self.store.due_scheduled_changes(int(time.time()), limit=3)
        for job in due_jobs:
            if not self.store.claim_scheduled_change(job.id):
                continue
            if not self.is_authorized(job.chat_id):
                self.store.finish_scheduled_change(job.id, "failed", "chat is no longer authorized")
                continue
            try:
                self.telegram.send_message(
                    job.chat_id,
                    f"计划任务到点，正在更换 {safe_target_name(job.target_name, job.router_id, job.interface)} 的 IP…",
                )

                if self.config.ippanel_mode == "api":
                    result = self.begin_api_change(
                        job.chat_id,
                        0,
                        job.router_id,
                        job.interface,
                        scheduled_job_id=job.id,
                    )
                    self.telegram.send_message(
                        job.chat_id,
                        telegram_html(f"计划任务\n{result}"),
                        parse_mode="HTML",
                    )
                    continue

                def progress(text: str) -> None:
                    self.telegram.send_message(job.chat_id, f"计划任务\n{text}")

                result = self.run_change(job.router_id, job.interface, progress)
                ddns_result = self.sync_ddns_after_change(
                    job.chat_id, job.router_id, job.interface
                )
                if ddns_result:
                    result = f"{result}\n\n{ddns_result}"
                relay_result = self.sync_relay_after_change(job.router_id, job.interface)
                if relay_result:
                    result = f"{result}\n\n{relay_result}"
                next_run_at = next_recurring_run_at(job, int(time.time()))
                if next_run_at:
                    self.store.reschedule_scheduled_change(job.id, next_run_at)
                    job_tz_name = job.timezone_name or self.config.timezone_name
                    job_tz = load_timezone(job_tz_name)
                    self.telegram.send_message(
                        job.chat_id,
                        telegram_html(
                            "\n".join(
                                [
                                    "计划任务本次执行完成",
                                    result,
                                    f"下次执行：{format_run_time(next_run_at, job_tz, job_tz_name)}",
                                ]
                            )
                        ),
                        parse_mode="HTML",
                    )
                else:
                    self.store.finish_scheduled_change(job.id, "done")
                    self.telegram.send_message(
                        job.chat_id,
                        telegram_html(f"计划任务执行完成\n{result}"),
                        parse_mode="HTML",
                    )
            except Exception as exc:
                if (
                    isinstance(exc, IppanelTransientError)
                    and job.retry_count < self.config.change_max_attempts
                ):
                    logging.warning("Scheduled change hit transient panel error: %s", exc)
                    retry_count = job.retry_count + 1
                    retry_at = int(time.time()) + self.config.change_retry_delay_seconds
                    self.store.reschedule_scheduled_change(
                        job.id, retry_at, str(exc), retry_count=retry_count
                    )
                    try:
                        job_tz_name = job.timezone_name or self.config.timezone_name
                        job_tz = load_timezone(job_tz_name)
                        self.telegram.send_message(
                            job.chat_id,
                            "计划任务遇到临时面板错误，稍后会重试本次任务。\n"
                            f"错误：{exc}\n"
                            f"重试：{retry_count}/{self.config.change_max_attempts}\n"
                            f"重试时间：{format_run_time(retry_at, job_tz, job_tz_name)}",
                        )
                    except Exception:
                        logging.exception("Failed to send scheduled job retry message")
                    continue

                logging.exception("Scheduled change failed")
                next_run_at = next_recurring_run_at(job, int(time.time()))
                if next_run_at:
                    self.store.reschedule_scheduled_change(job.id, next_run_at, str(exc))
                else:
                    self.store.finish_scheduled_change(job.id, "failed", str(exc))
                try:
                    if next_run_at:
                        job_tz_name = job.timezone_name or self.config.timezone_name
                        job_tz = load_timezone(job_tz_name)
                        self.telegram.send_message(
                            job.chat_id,
                            f"计划任务本次执行失败：{exc}\n"
                            f"下次仍按计划执行：{format_run_time(next_run_at, job_tz, job_tz_name)}",
                        )
                    else:
                        self.telegram.send_message(job.chat_id, f"计划任务执行失败：{exc}")
                except Exception:
                    logging.exception("Failed to send scheduled job failure message")

    def send_long(self, chat_id: int, text: str) -> None:
        chunk = ""
        for line in text.splitlines():
            candidate = f"{chunk}\n{line}" if chunk else line
            if len(candidate) > 3800:
                self.telegram.send_message(chat_id, chunk)
                chunk = line
            else:
                chunk = candidate
        if chunk:
            self.telegram.send_message(chat_id, chunk)


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level, logging.INFO),
        format="%(asctime)s %(levelname)s %(message)s",
    )


def make_panel_client(config: Config) -> IppanelClient | IppanelApiClient:
    if config.ippanel_mode == "api":
        return IppanelApiClient(
            config.ippanel_base_url,
            config.ippanel_api_targets,
            config.query_cache_seconds,
        )
    return IppanelClient(
        config.ippanel_base_url,
        config.ippanel_account,
        config.ippanel_password,
        config.query_cache_seconds,
    )


def cli_print_vps_list(zones: list[ZoneItem]) -> None:
    if not zones:
        print("没有从面板查到 VPS。")
        return
    for index, zone in enumerate(zones, start=1):
        print(f"{index}. {zone.display_name}")
        print(f"   当前公网 IP: {zone.current_ip or '未找到'}")
        print(f"   内网 IP: {zone.dedicated_ip or '未返回'}")
        print(f"   router_id: {zone.router_id}")
        print(f"   interface: {zone.interface}")
        print(f"   状态: {status_label(zone)}")


def cli_list_vps(config: Config) -> int:
    panel = make_panel_client(config)
    payload = panel.query_all(force=True)
    cli_print_vps_list(parse_zones(payload))
    return 0


def prompt_cli(label: str, default: str = "", required: bool = False, secret: bool = False) -> str:
    while True:
        suffix = f" [{default}]" if default else ""
        prompt = f"{label}{suffix}: "
        value = getpass.getpass(prompt) if secret else input(prompt)
        value = value.strip() or default
        if required and not value:
            print(f"{label} 不能为空。")
            continue
        return value


def prompt_cli_int(label: str, minimum: int, maximum: int) -> int:
    while True:
        value = input(label).strip()
        if value.isdigit() and minimum <= int(value) <= maximum:
            return int(value)
        print(f"请输入 {minimum}-{maximum} 之间的数字。")


def cli_print_relay_bindings(bindings: list[RelayBinding], config: Config) -> None:
    if not bindings:
        print("当前没有中转同步绑定。")
        return
    timezone_value = load_timezone(config.timezone_name)
    for index, binding in enumerate(bindings, start=1):
        print(f"{index}. {binding.target_name}")
        print(f"   Receiver: {relay_host_label(binding.receiver_url)}")
        print(f"   target_name: {binding.receiver_target_name}")
        print(f"   匹配模式: {relay_match_mode_label(binding.match_mode)}")
        if binding.last_sync_at:
            print(
                "   上次同步: "
                f"{format_run_time(binding.last_sync_at, timezone_value, config.timezone_name)}"
            )
        if binding.last_error:
            print(f"   上次错误: {binding.last_error}")


def cli_list_relay_bindings(config: Config) -> int:
    store = BotStore(config.db_path)
    try:
        cli_print_relay_bindings(store.list_relay_bindings(), config)
    finally:
        store.close()
    return 0


def cli_choose_relay_binding(config: Config) -> tuple[BotStore, RelayBinding] | None:
    store = BotStore(config.db_path)
    bindings = store.list_relay_bindings()
    if not bindings:
        print("当前没有中转同步绑定。")
        store.close()
        return None
    cli_print_relay_bindings(bindings, config)
    choice = prompt_cli_int("请输入绑定序号: ", 1, len(bindings))
    return store, bindings[choice - 1]


def cli_configure_relay(config: Config) -> int:
    panel = make_panel_client(config)
    payload = panel.query_all(force=True)
    zones = parse_zones(payload)
    if not zones:
        print("没有从面板查到 VPS，无法配置中转同步。")
        return 1

    print("请选择要绑定中转同步的 Boil VPS：")
    cli_print_vps_list(zones)
    choice = prompt_cli_int("请输入序号: ", 1, len(zones))
    zone = zones[choice - 1]
    if not zone.dedicated_ip and zone.interface == API_INTERFACE:
        print("API 模式将使用本地机器 ID 校验绑定。")
    elif not zone.dedicated_ip:
        print("这台 VPS 没有返回内网 IP，无法创建安全绑定。")
        return 1

    print("")
    print("请输入 ippanelreceiver 信息。")
    print("项目地址：https://github.com/DarkJimiHole/ippanelreceiver")
    receiver_url = validate_relay_url(prompt_cli("Receiver 上报地址", required=True))
    reporter = prompt_cli("Reporter ID", "bot-main", required=True)
    secret = prompt_cli("上报密钥", required=True, secret=True)
    receiver_target_name = prompt_cli("target_name", "target1", required=True)
    match_mode = normalize_relay_match_mode(
        prompt_cli("匹配模式 remark/old_ip/old_ip_unique", "remark", required=True)
    )

    store = BotStore(config.db_path)
    try:
        binding_id = store.upsert_relay_binding(
            router_id=zone.router_id,
            interface=zone.interface,
            internal_ip=zone.dedicated_ip,
            target_name=zone.display_name,
            receiver_url=receiver_url,
            reporter=reporter,
            secret=secret,
            receiver_target_name=receiver_target_name,
            match_mode=match_mode,
            last_ip=zone.current_ip,
        )
    finally:
        store.close()

    print("")
    print(f"中转同步绑定已保存：#{binding_id}")
    print(f"目标 VPS: {zone.display_name}")
    print(f"中转 VPS: {relay_host_label(receiver_url)}")
    print(f"target_name: {receiver_target_name}")
    print(f"匹配模式: {match_mode}")
    print("Telegram 里只会显示绑定结果、目标名称和匹配模式。")
    return 0


def cli_edit_relay_binding(config: Config) -> int:
    selected = cli_choose_relay_binding(config)
    if selected is None:
        return 1
    store, binding = selected
    try:
        print("")
        print("修改中转同步绑定。直接回车会保留当前值。")
        receiver_url = validate_relay_url(
            prompt_cli("Receiver 上报地址", binding.receiver_url, required=True)
        )
        reporter = prompt_cli("Reporter ID", binding.reporter, required=True)
        secret = getpass.getpass("上报密钥 [直接回车保留原密钥]: ").strip() or binding.secret
        receiver_target_name = prompt_cli(
            "target_name", binding.receiver_target_name, required=True
        )
        match_mode = normalize_relay_match_mode(
            prompt_cli(
                "匹配模式 remark/old_ip/old_ip_unique",
                binding.match_mode,
                required=True,
            )
        )
        try:
            updated = store.update_relay_binding(
                binding.id,
                receiver_url,
                reporter,
                secret,
                receiver_target_name,
                match_mode,
            )
        except sqlite3.IntegrityError:
            print("修改失败：相同 Receiver 和 target_name 的绑定已存在。")
            return 1
        if not updated:
            print("修改失败：绑定不存在。")
            return 1
    finally:
        store.close()

    print("")
    print("中转同步绑定已修改。")
    return 0


def cli_delete_relay_binding(config: Config) -> int:
    selected = cli_choose_relay_binding(config)
    if selected is None:
        return 1
    store, binding = selected
    try:
        print("")
        print(f"将删除绑定：{binding.target_name} / {binding.receiver_target_name}")
        confirm = prompt_cli_int("确认删除，0=取消，1=删除: ", 0, 1)
        if confirm != 1:
            print("已取消。")
            return 0
        if not store.delete_relay_binding(binding.id):
            print("删除失败：绑定不存在。")
            return 1
    finally:
        store.close()

    print("中转同步绑定已删除。")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="IPPanelBot")
    parser.add_argument(
        "command",
        nargs="?",
        default="run",
        choices=("run", "list-vps", "relay", "relay-list", "relay-edit", "relay-delete"),
        help="run bot, list panel VPS, or manage relay sync",
    )
    args = parser.parse_args()

    try:
        config = read_config()
    except ConfigError as exc:
        print(f"Config error: {exc}", file=sys.stderr)
        return 2

    configure_logging(config.log_level)
    if args.command == "list-vps":
        return cli_list_vps(config)
    if args.command == "relay":
        return cli_configure_relay(config)
    if args.command == "relay-list":
        return cli_list_relay_bindings(config)
    if args.command == "relay-edit":
        return cli_edit_relay_binding(config)
    if args.command == "relay-delete":
        return cli_delete_relay_binding(config)

    try:
        app = BotApp(config)
    except ConfigError as exc:
        print(f"Config error: {exc}", file=sys.stderr)
        return 2
    signal.signal(signal.SIGTERM, app.request_stop)
    signal.signal(signal.SIGINT, app.request_stop)
    app.run()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n已取消。", file=sys.stderr)
        raise SystemExit(130)
