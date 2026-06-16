import base64
import hashlib
import json
import os
from pathlib import Path


SECRET_KEYS = {
    "otx_api_key",
    "virustotal_api_key",
    "abuseipdb_api_key",
    "greynoise_api_key",
    "shodan_api_key",
    "malwarebazaar_api_key",
    "ipinfo_api_key",
}


def _config_dir() -> Path:
    return Path(os.environ.get("OTX_SEC_SECRET_DIR", Path.home() / ".config" / "otx-sec"))


def _key_file() -> Path:
    return _config_dir() / "master.key"


def _secret_file() -> Path:
    return _config_dir() / "secrets.json"


def init_secret_store() -> None:
    base = _config_dir()
    base.mkdir(parents=True, exist_ok=True)

    key_file = _key_file()
    secret_file = _secret_file()

    if not key_file.exists():
        key_file.write_text(os.urandom(32).hex())

    if not secret_file.exists():
        secret_file.write_text(json.dumps({}, indent=2))

    try:
        os.chmod(base, 0o700)
        os.chmod(key_file, 0o600)
        os.chmod(secret_file, 0o600)
    except Exception:
        pass


def _load_key() -> bytes:
    init_secret_store()
    raw = _key_file().read_text().strip()
    return hashlib.sha256(raw.encode("utf-8")).digest()


def _xor(data: bytes, key: bytes) -> bytes:
    return bytes(byte ^ key[index % len(key)] for index, byte in enumerate(data))


def encrypt_value(value: str) -> str:
    if not value:
        return ""

    key = _load_key()
    encrypted = _xor(value.encode("utf-8"), key)
    return base64.urlsafe_b64encode(encrypted).decode("ascii")


def decrypt_value(value: str) -> str:
    if not value:
        return ""

    key = _load_key()
    encrypted = base64.urlsafe_b64decode(value.encode("ascii"))
    return _xor(encrypted, key).decode("utf-8", errors="replace")


def load_secrets() -> dict:
    init_secret_store()

    try:
        data = json.loads(_secret_file().read_text())
    except Exception:
        return {}

    result = {}

    for key, value in data.items():
        try:
            result[key] = decrypt_value(value)
        except Exception:
            result[key] = ""

    return result


def save_secrets(data: dict) -> None:
    init_secret_store()

    encrypted = {}

    for key in SECRET_KEYS:
        value = str(data.get(key, "")).strip()
        encrypted[key] = encrypt_value(value)

    _secret_file().write_text(json.dumps(encrypted, indent=2, ensure_ascii=False))

    try:
        os.chmod(_secret_file(), 0o600)
    except Exception:
        pass


def split_settings_and_secrets(data: dict) -> tuple[dict, dict]:
    public_settings = {}
    secret_settings = {}

    for key, value in data.items():
        if key in SECRET_KEYS:
            secret_settings[key] = value
        else:
            public_settings[key] = value

    return public_settings, secret_settings


def merge_settings_with_secrets(settings: dict) -> dict:
    merged = dict(settings)
    merged.update(load_secrets())
    return merged
