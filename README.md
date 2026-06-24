# misp-interactive-event

A guided, interactive CLI tool for creating DDoS events in [MISP](https://www.misp-project.org/), following the Streamlined MISP DDoS Playbook.

It walks you through prompts for all event details - with validation at every step - then creates a properly structured event in your MISP instance.

## What it creates

Each event is created with:

- **TLP tag** of your choice (`clear`, `green`, `amber`, `red`)
- **MITRE ATT&CK T1498** (Network Denial of Service) galaxy cluster
- **Workflow state** `draft`
- An **`ip-port` object** containing attacker (source) IPs, and optional destination IPs/ports
- An **`annotation` object** with your description
- Optional **TLS fingerprints** (JA3/JA3S/JA4 family as MISP objects; JARM/HASSH as attributes)

## Why it's minimal

- **No auto-update, no subprocess calls** - the tool never shells out or contacts anything other than your configured MISP URL.
- Single, focused command (no bundled sub-commands).
- Inline configuration loading - easy to read and audit.

## Requirements

- Python 3.8+
- Dependencies in [requirements.txt](requirements.txt) (`pymisp`, `click`, `rich`, `python-dotenv`)

## Installation

```bash
git clone https://github.com/mispquickshareorg/misp-interactive-event.git
cd misp-interactive-event
pip install -r requirements.txt
```

## Configuration

Copy the example environment file and fill in your MISP details:

```bash
cp .env.example .env
```

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `MISP_URL` | Yes | - | Base URL of your MISP instance (`https://...`) |
| `MISP_API_KEY` | Yes | - | Your MISP API authentication key |
| `MISP_VERIFY_SSL` | No | `true` | Set to `false` for self-signed certificates |
| `MISP_TIMEOUT` | No | `30` | Request timeout in seconds |

> **Note:** `.env` is git-ignored. Never commit real credentials.

## Usage

```bash
# Launch the interactive event creator
python main.py

# Use a specific env file
python main.py --env-file /path/to/.env

# Enable debug logging
python main.py --debug
```

You'll be prompted for the event name, date, annotation, attacker IPs, optional destination IPs, TLP level, and optional TLS fingerprints. A summary is shown for confirmation before anything is sent to MISP.

## Security notes

- The API key is read from the environment only and is never logged.
- The only network destination is the `MISP_URL` you configure.
- All inputs (IPs, dates, ports, fingerprints) are validated before submission.

## License

MIT
