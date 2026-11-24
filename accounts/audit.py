import hashlib
import json
import threading
from datetime import datetime, timedelta, timezone

from django.conf import settings

LOG_FILE = settings.LOG_DIR / "dziennik.json"
HASH_FILE = settings.LOG_DIR / "dziennik.sha256"
ALERT_FILE = settings.LOG_DIR / "alerty.json"
TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

ACTIONS = {
    "LOGOWANIE": "Logowanie",
    "LOGOWANIE_NIEUDANE": "Nieudane logowanie",
    "WYLOGOWANIE": "Wylogowanie",
    "BLOKADA_KONTA": "Blokada konta",
    "ZMIANA_HASLA": "Zmiana hasła",
    "UZYTKOWNIK_DODANY": "Dodanie użytkownika",
    "UZYTKOWNIK_ZMIENIONY": "Edycja użytkownika",
    "ZMIANA_ROLI": "Zmiana roli",
    "UZYTKOWNIK_ZABLOKOWANY": "Zablokowanie użytkownika",
    "UZYTKOWNIK_ODBLOKOWANY": "Odblokowanie użytkownika",
    "UZYTKOWNIK_USUNIETY": "Usunięcie użytkownika",
    "RESET_HASLA": "Reset hasła",
    "ZMIANA_USTAWIEN": "Zmiana ustawień",
    "ODMOWA_DOSTEPU": "Odmowa dostępu",
    "KONTO_PULAPKA": "Użycie konta-pułapki",
    "EKSPORT_DZIENNIKA": "Eksport dziennika",
    "WERYFIKACJA_DZIENNIKA": "Weryfikacja dziennika",
    "ALERT": "Alert",
}

RULES = {
    "LOGOWANIE_NIEUDANE": (5, 5, "co najmniej 5 nieudanych logowań na jedno konto w ciągu 5 minut"),
    "ODMOWA_DOSTEPU": (3, 10, "co najmniej 3 odmowy dostępu dla jednego użytkownika w ciągu 10 minut"),
}

lock = threading.RLock()


def now():
    return datetime.now(timezone.utc).strftime(TIME_FORMAT)


def clean(value, limit=200):
    return "".join(char for char in str(value) if char.isprintable())[:limit]


def read_json(path):
    if not path.exists():
        return []
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except ValueError:
        return None


def write_json(path, data):
    settings.LOG_DIR.mkdir(exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def file_hash():
    if not LOG_FILE.exists():
        return ""
    return hashlib.sha256(LOG_FILE.read_bytes()).hexdigest()


def stored_hash():
    if not HASH_FILE.exists():
        return ""
    return HASH_FILE.read_text().strip()


def verify():
    return file_hash() == stored_hash()


def save_alert(rule, username, description):
    with lock:
        alerts = read_json(ALERT_FILE) or []
        alerts.append({"czas": now(), "regula": rule, "uzytkownik": clean(username), "opis": clean(description, 500)})
        write_json(ALERT_FILE, alerts)


def log_event(request, action, description, success, username=None):
    if username is None:
        username = request.user.username if request.user.is_authenticated else "-"
    entry = {
        "czas": now(),
        "uzytkownik": clean(username, 150),
        "ip": request.META.get("REMOTE_ADDR", ""),
        "akcja": action,
        "opis": clean(description),
        "wynik": "sukces" if success else "błąd",
    }
    with lock:
        intact = verify()
        entries = read_json(LOG_FILE)
        if entries is None:
            save_alert("Uszkodzony dziennik", entry["uzytkownik"], f"Nie można odczytać dziennika. Zdarzenie: {action}, {entry['opis']}")
            return
        entries.append(entry)
        write_json(LOG_FILE, entries)
        if intact:
            HASH_FILE.write_text(file_hash())
    check_rules(request, entries, entry)


def check_rules(request, entries, entry):
    rule = RULES.get(entry["akcja"])
    if rule is None:
        return
    limit, minutes, name = rule
    since = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).strftime(TIME_FORMAT)
    count = 0
    for item in entries:
        if item.get("akcja") == entry["akcja"] and item.get("uzytkownik") == entry["uzytkownik"] and item.get("czas", "") >= since:
            count += 1
    if count == limit:
        description = f"Reguła: {name}. Konto: {entry['uzytkownik']}"
        save_alert(name, entry["uzytkownik"], description)
        log_event(request, "ALERT", description, False, entry["uzytkownik"])


def filter_entries(entries, user="", action="", date_from="", date_to=""):
    result = []
    for entry in reversed(entries):
        day = entry.get("czas", "")[:10]
        if user and user.lower() not in entry.get("uzytkownik", "").lower():
            continue
        if action and entry.get("akcja") != action:
            continue
        if date_from and day < date_from:
            continue
        if date_to and day > date_to:
            continue
        result.append(entry)
    return result