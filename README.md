# metalog

Automates login to the EDS Cloud Platform and downloads the last 24 hours of data per device/channel.

## Setup

1) Install Python deps:

```bash
pip install -r requirements.txt
python -m playwright install
```

2) Create an optional config file:

```bash
cp config.example.json config.json
```

3) Choose one credential option:

- Encrypted file (prompt for passphrase each run):

```bash
python metalog.py encrypt
```

- OS keychain (no prompt during fetch):

```bash
python metalog.py store
```

If using keychain, set `auth_mode` to `keyring` in your config (see example).

```bash
python metalog.py encrypt
```

## Run

```bash
python metalog.py fetch
```

To force keychain auth without editing config:

```bash
python metalog.py fetch --auth keyring
```

Downloads are stored in `./downloads/YYYY-MM-DD/` by default.

## Scheduling (daily)

Example cron entry (runs at 2:15 AM daily):

```bash
15 2 * * * /usr/bin/python3 /path/to/metalog.py fetch --secrets /path/to/secrets.enc --config /path/to/config.json
```

Adjust the time or cadence as needed.