# 🛡️ VulnWatcher Bot

A stateful monitoring tool for infrastructure-specific Vulnerability Management. It automates the detection and prioritization of CVEs affecting a defined asset stack.

Flow:

```
[ targets.yaml ]          [ .env config ]
              |                        |
              v                        v
    +--------------------------------------------+
    |           VulnWatcher Engine (Async)       |
    +--------------------------------------------+
              |
              | 1. Request (per query + 5s delay)
              v
    +-----------------------+      +-----------------------+
    |   ProjectDiscovery    | <--- |   PDCP API (v2)       |
    |      CVEMap API       | ---> |  (Raw JSON Data)      |
    +-----------------------+      +-----------------------+
              |
              | 2. Filter (doc_type == "cve")
              v
    +-----------------------+      +-----------------------+
    |    Decision Engine    | <--- |   vuln_states.db      |
    | (State Comparison)    | ---> |  (SQLite Tracking)    |
    +-----------------------+      +-----------------------+
              |
              | 3. If New or Status Changed (PoC/Exploit)
              v
    +-----------------------+      +-----------------------+
    |  MarkdownV2 Encoder   |      |   Telegram Bot API    |
    | (Regex Escaping)      | ---> |   (Styled Alerts)     |
    +-----------------------+      +-----------------------+
              |
              +-----------> [ 🚨 Alert ]
```

## Key Features

- Asset-Based Monitoring: Track specific products (e.g., FortiOS, Exchange, Citrix) via keyword queries.
- Weaponization Alerts: Distinct notifications for new CVEs, PoC releases, and "In-the-wild" exploitation.
- Stateful Tracking: Uses a local SQLite database to prevent duplicate alerts and track status changes.

## Quick Start

1. Prerequisites

- Python 3.10+

- A ProjectDiscovery Cloud (PDCP) API Key.

- A Telegram Bot Token (from @BotFather).

2. Installation

```bash
git clone https://github.com/s0ld13rr/vulnwatcher-bot.git
cd vulnwatcher-bot
pip install -r requirements.txt
```

3. Configuration

Create a `.env` file:

```PDCP_API_KEY=your_pdcp_key
TG_BOT_TOKEN=your_bot_token
TG_CHAT_ID=your_chat_id
MIN_CVSS=7.5
```

Edit `targets.yaml` to define products to monitor:

```
queries:
  - "fortios"
  - "exchange"
  - "globalprotect"
  - "citrix"
```

4. Running the bot

```bash
python3 app.py
```

Then, you may create a cron-job on your VPS to re-check the vulns defined in your `targets.yaml`. 

## TODO 

- Add OpenCVE API
- Make more meaningful alerts on Telegram
