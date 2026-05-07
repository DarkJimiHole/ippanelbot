# IPPanelBot

IPPanelBot is an interactive Telegram bot and Bash management script for changing BoilCloud IP addresses through `https://ippanel.boil.network`.

It is built only for `https://ippanel.boil.network`, also known as `BoilのIP管理Panel`. It is not a general-purpose IP management bot for other providers or panels.

The bot uses Telegram long polling and the panel backend APIs, so you can query machines, change IP addresses, and schedule IP changes from Telegram without deploying the bot on the dynamic-IP VPS itself.

## Features

- Manage BoilCloud IP changes from Telegram
- Query current machine name, public IP, bound IP, and remaining change quota
- Change IP immediately, after a delay, or by scheduled tasks
- Retry failed IP changes automatically after a configurable interval
- Auto-login again when the panel session expires
- Store delayed and scheduled tasks in SQLite
- Optional Cloudflare DDNS per VPS
- Configurable Cloudflare DDNS TTL
- Auto-create Telegram command menu on startup
- Command `boil`

## Usage

```bash
bash <(curl -Ls https://raw.githubusercontent.com/DarkJimiHole/ippanelbot/main/ippanelbot.sh)
```

If you downloaded the repository manually:

```bash
sudo bash ippanelbot.sh install
```

## Menu

```text
1. 安装
2. 修改配置
3. 更新文件
4. 启动
5. 停止
6. 重启
7. 查看状态
8. 查看日志
9. 卸载
0. 退出
```

## Commands

```bash
sudo boil install
sudo boil config
sudo boil update
sudo boil start
sudo boil stop
sudo boil restart
sudo boil status
sudo boil logs
sudo boil uninstall
```

## Telegram Commands

```text
/start
/ip
/change
/jobs
/canceljob 1
/ddns
/ddnsdel 1
/cancel
/help
```

## What The Script Manages

- bot script: `/opt/ippanelbot/bot.py`
- panel image: `/opt/ippanelbot/pic.png`
- shortcut command: `/usr/local/bin/boil`
- environment file: `/etc/ippanelbot.env`
- download source file: `/etc/ippanelbot.source`
- SQLite data directory: `/var/lib/ippanelbot`
- SQLite database: `/var/lib/ippanelbot/ippanel_bot.sqlite3`
- systemd service: `/etc/systemd/system/ippanelbot.service`
- system user: `ippanelbot`

## Configuration

During installation, the script asks for:

- Telegram bot token
- allowed Telegram chat IDs
- BoilCloud panel account
- BoilCloud panel password
- post-change query delay seconds
- query cache seconds
- change retry attempts
- change retry interval seconds
- scheduled task timezone
- Telegram polling timeout seconds
- DDNS switch
- Cloudflare API token, Zone ID, and DNS TTL

When DDNS is enabled, the Telegram bot only asks for the hostname for each VPS. The bot stores the selected VPS by its internal panel identity and syncs the Cloudflare A record to that VPS current public IP.

Cloudflare TTL defaults to `60` seconds. Enter `1` only if you want Cloudflare Auto TTL.

The timezone uses an IANA timezone name, for example:

```text
Asia/Shanghai
Asia/Hong_Kong
UTC
America/Los_Angeles
```

If no timezone is entered, the script uses the server timezone. If that cannot be detected, it uses `Asia/Shanghai`.

## Notes

- This bot only works with `https://ippanel.boil.network` / `BoilのIP管理Panel`.
- The installer targets Debian 12 and uses Python 3 from the system package manager.
- No third-party Python packages are required.
- The script stores the GitHub raw source after installation, so `sudo boil update` can download future updates from this repository.
- DDNS currently supports Cloudflare only.

## License

Use at your own risk.
