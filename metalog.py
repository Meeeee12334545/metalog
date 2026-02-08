#!/usr/bin/env python3
import argparse
import base64
import datetime as dt
import getpass
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import keyring
from playwright.sync_api import sync_playwright

DEFAULT_CONFIG = {
    "base_url": "http://www.m2m-iot.cc/sign/showLogin#",
    "headless": True,
    "slow_mo_ms": 0,
    "download_dir": "./downloads",
    "auth_mode": "encrypted",
    "keyring_service": "metalog_m2m_iot",
    "history": {
        "start_label": "Server Start Date",
        "end_label": "Server End Date",
        "date_format": "%m/%d/%Y",
        "search_button_text": "search",
        "save_excel_text": "SaveExcel",
    },
}


@dataclass
class Secrets:
    username: str
    password: str


@dataclass
class DeviceLink:
    name: str
    device_id: str
    href: Optional[str]
    onclick: Optional[str]
    row_index: int


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend(),
    )
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))


def encrypt_secrets(secrets_path: Path) -> None:
    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")
    passphrase = getpass.getpass("Passphrase (used to encrypt): ")
    confirm = getpass.getpass("Confirm passphrase: ")
    if passphrase != confirm:
        raise SystemExit("Passphrase mismatch.")

    salt = os.urandom(16)
    key = _derive_key(passphrase, salt)
    fernet = Fernet(key)
    payload = json.dumps({"username": username, "password": password}).encode("utf-8")
    token = fernet.encrypt(payload)

    secrets = {
        "salt": base64.b64encode(salt).decode("ascii"),
        "token": token.decode("ascii"),
    }
    secrets_path.write_text(json.dumps(secrets, indent=2), encoding="utf-8")
    print(f"Encrypted credentials saved to {secrets_path}")


def store_keyring(service: str) -> None:
    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")
    payload = json.dumps({"username": username, "password": password})
    keyring.set_password(service, "credentials", payload)
    print(f"Credentials stored in keychain service '{service}'.")


def load_secrets_keyring(service: str) -> Secrets:
    payload = keyring.get_password(service, "credentials")
    if not payload:
        raise SystemExit(
            "No keychain credentials found. Run 'python metalog.py store'."
        )
    obj = json.loads(payload)
    return Secrets(username=obj["username"], password=obj["password"])


def load_secrets(secrets_path: Path) -> Secrets:
    if not secrets_path.exists():
        raise SystemExit(f"Secrets file not found: {secrets_path}")

    data = json.loads(secrets_path.read_text(encoding="utf-8"))
    passphrase = getpass.getpass("Passphrase (to decrypt): ")
    salt = base64.b64decode(data["salt"])
    key = _derive_key(passphrase, salt)
    fernet = Fernet(key)

    try:
        payload = fernet.decrypt(data["token"].encode("ascii"))
    except Exception as exc:  # pragma: no cover
        raise SystemExit("Failed to decrypt. Check passphrase.") from exc

    obj = json.loads(payload.decode("utf-8"))
    return Secrets(username=obj["username"], password=obj["password"])


def load_config(config_path: Optional[Path]) -> Dict:
    config = json.loads(json.dumps(DEFAULT_CONFIG))
    if config_path and config_path.exists():
        user_config = json.loads(config_path.read_text(encoding="utf-8"))
        config.update(user_config)
        if "history" in user_config:
            config["history"].update(user_config["history"])
    return config


def _safe_name(value: str) -> str:
    value = re.sub(r"\s+", "_", value.strip())
    value = re.sub(r"[^A-Za-z0-9_.-]+", "", value)
    return value or "unknown"


def _extract_url(text: Optional[str]) -> Optional[str]:
    if not text:
        return None
    match = re.search(r"(https?://[^'\")]+|/[^'\")]+)", text)
    if match:
        return match.group(1)
    return None


def _set_date_by_label(page, label_text: str, value: str) -> bool:
    script = """
    (labelText, value) => {
      const nodes = Array.from(document.querySelectorAll('label, span, div'));
      const target = nodes.find(n => n.textContent && n.textContent.trim().startsWith(labelText));
      if (!target) return false;
      let input = target.querySelector('input');
      if (!input && target.parentElement) {
        input = target.parentElement.querySelector('input');
      }
      if (!input && target.nextElementSibling) {
        if (target.nextElementSibling.tagName === 'INPUT') {
          input = target.nextElementSibling;
        } else {
          input = target.nextElementSibling.querySelector('input');
        }
      }
      if (!input) return false;
      input.value = value;
      input.dispatchEvent(new Event('input', { bubbles: true }));
      input.dispatchEvent(new Event('change', { bubbles: true }));
      return true;
    }
    """
    return bool(page.evaluate(script, label_text, value))


def _find_devices(page) -> List[DeviceLink]:
    rows = page.locator("table tbody tr")
    count = rows.count()
    devices: List[DeviceLink] = []

    for i in range(count):
        row = rows.nth(i)
        link = row.locator("a:has-text('Realtime View')").first
        if link.count() == 0:
            continue
        href = link.get_attribute("href")
        onclick = link.get_attribute("onclick")
        cells = row.locator("td")
        device_id = cells.nth(1).inner_text().strip() if cells.count() > 1 else f"device_{i+1}"
        device_name = cells.nth(2).inner_text().strip() if cells.count() > 2 else device_id
        devices.append(DeviceLink(device_name, device_id, href, onclick, i))

    return devices


def _open_device_page(context, list_page, base_url: str, device: DeviceLink):
    url = _extract_url(device.href) or _extract_url(device.onclick)
    if url:
        new_page = context.new_page()
        new_page.goto(urljoin(base_url, url), wait_until="networkidle")
        return new_page

    link = list_page.locator("a:has-text('Realtime View')").nth(device.row_index)
    with list_page.expect_popup() as popup:
        link.click()
    new_page = popup.value
    new_page.wait_for_load_state("networkidle")
    return new_page


def _download_history(page, device: DeviceLink, download_dir: Path, history_cfg: Dict) -> None:
    now = dt.datetime.now()
    start = now - dt.timedelta(hours=24)
    date_format = history_cfg.get("date_format", "%m/%d/%Y")

    start_val = start.strftime(date_format)
    end_val = now.strftime(date_format)

    if not _set_date_by_label(page, history_cfg.get("start_label", "Server Start Date"), start_val):
        page.locator("input[type='text']").first.fill(start_val)
    if not _set_date_by_label(page, history_cfg.get("end_label", "Server End Date"), end_val):
        inputs = page.locator("input[type='text']")
        if inputs.count() > 1:
            inputs.nth(1).fill(end_val)

    search_text = history_cfg.get("search_button_text", "search")
    page.locator(f"text={search_text}").first.click()

    save_text = history_cfg.get("save_excel_text", "SaveExcel")
    with page.expect_download() as download_info:
        page.locator(f"text={save_text}").first.click()
    download = download_info.value

    download_dir.mkdir(parents=True, exist_ok=True)
    device_name = _safe_name(device.name)
    filename = f"{device_name}__{start.strftime('%Y%m%d')}__{end.strftime('%Y%m%d')}.xlsx"
    target = download_dir / filename
    download.save_as(target.as_posix())


def _process_device(context, device: DeviceLink, list_page, base_url: str, download_dir: Path, history_cfg: Dict) -> None:
    page = _open_device_page(context, list_page, base_url, device)
    try:
        if page.locator("text=SaveExcel").count() > 0:
            _download_history(page, device, download_dir, history_cfg)
            return

        rows = page.locator("table tbody tr")
        row_count = rows.count()
        if row_count == 0:
            print(f"No channels found for {device.name}")
            return

        for idx in range(row_count):
            row = rows.nth(idx)
            cells = row.locator("td")
            channel_name = cells.nth(0).inner_text().strip() if cells.count() > 0 else f"channel_{idx+1}"
            link = row.locator("a").first
            if link.count() == 0:
                continue
            href = link.get_attribute("href")
            onclick = link.get_attribute("onclick")
            url = _extract_url(href) or _extract_url(onclick)
            if url:
                chan_page = context.new_page()
                chan_page.goto(urljoin(base_url, url), wait_until="networkidle")
            else:
                with page.expect_popup() as popup:
                    link.click()
                chan_page = popup.value
                chan_page.wait_for_load_state("networkidle")

            try:
                _download_history(
                    chan_page,
                    DeviceLink(
                        f"{device.name}_{channel_name}",
                        device.device_id,
                        None,
                        None,
                        device.row_index,
                    ),
                    download_dir / _safe_name(device.name),
                    history_cfg,
                )
            finally:
                chan_page.close()
    finally:
        page.close()


def run_fetch(secrets_path: Path, config_path: Optional[Path], auth_mode: Optional[str]) -> None:
    config = load_config(config_path)
    mode = (auth_mode or config.get("auth_mode") or "encrypted").lower()
    if mode == "keyring":
        secrets = load_secrets_keyring(config.get("keyring_service", "metalog_m2m_iot"))
    else:
        secrets = load_secrets(secrets_path)
    base_url = config["base_url"]
    download_dir = Path(config.get("download_dir", "./downloads"))

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=bool(config.get("headless", True)),
            slow_mo=int(config.get("slow_mo_ms", 0)),
        )
        context = browser.new_context(accept_downloads=True)
        page = context.new_page()

        page.goto(base_url, wait_until="networkidle")
        page.locator("input[type='text']").first.fill(secrets.username)
        page.locator("input[type='password']").first.fill(secrets.password)
        page.locator("button, input[type='submit']").first.click()
        page.wait_for_load_state("networkidle")

        page.locator("text=All devices").first.click()
        page.wait_for_load_state("networkidle")

        devices = _find_devices(page)
        if not devices:
            raise SystemExit("No devices found. Check selectors or permissions.")

        day_dir = download_dir / dt.datetime.now().strftime("%Y-%m-%d")
        for device in devices:
            print(f"Downloading for {device.name} ({device.device_id})")
            _process_device(context, device, page, base_url, day_dir, config["history"])

        context.close()
        browser.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Download latest 24h data from EDS Cloud Platform.")
    parser.add_argument(
        "--secrets",
        default="./secrets.enc",
        help="Path to encrypted credentials file (default: ./secrets.enc)",
    )
    parser.add_argument(
        "--config",
        default="./config.json",
        help="Path to config file (default: ./config.json)",
    )
    parser.add_argument(
        "--auth",
        choices=["encrypted", "keyring"],
        help="Auth mode override (encrypted or keyring)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("encrypt", help="Encrypt username/password into secrets file")
    sub.add_parser("store", help="Store credentials in OS keychain")
    sub.add_parser("fetch", help="Login and download latest 24h data")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    secrets_path = Path(args.secrets)
    config_path = Path(args.config) if args.config else None

    if args.command == "encrypt":
        encrypt_secrets(secrets_path)
        return
    if args.command == "store":
        config = load_config(config_path)
        service = config.get("keyring_service", "metalog_m2m_iot")
        store_keyring(service)
        return
    if args.command == "fetch":
        run_fetch(secrets_path, config_path, args.auth)
        return

    raise SystemExit("Unknown command")


if __name__ == "__main__":
    main()
