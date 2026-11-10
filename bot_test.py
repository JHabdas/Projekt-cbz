import argparse
import re

import requests

DUMMY_TOKEN = "XXXX.DUMMY.TOKEN.XXXX"


def get_csrf(session, url):
    response = session.get(url)
    match = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', response.text)
    return response.url, match.group(1)


def try_login(base, username, password, token=None, honeypot=""):
    session = requests.Session()
    _, csrf = get_csrf(session, base + "/login/")
    data = {"csrfmiddlewaretoken": csrf, "username": username, "password": password, "website": honeypot}
    if token:
        data["cf-turnstile-response"] = token
    response = session.post(base + "/login/", data=data, allow_redirects=False)
    return session, response


def error_text(response):
    match = re.search(r'<p class="error">(.*?)</p>', response.text)
    return match.group(1) if match else ""


def logged_in(response):
    return response.status_code == 302


def main():
    parser = argparse.ArgumentParser(description="Symulacja bota atakującego logowanie (tylko własna aplikacja).")
    parser.add_argument("--url", default="http://127.0.0.1:8000")
    parser.add_argument("--user", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--target", default="jkowalski")
    parser.add_argument("--attempts", type=int, default=6)
    parser.add_argument("--trap", default="administrator")
    args = parser.parse_args()
    base = args.url.rstrip("/")
    results = []

    _, r = try_login(base, args.user, args.password)
    if logged_in(r):
        results.append(("Poprawne hasło, brak tokenu CAPTCHA", "ZALOGOWANO", "brak"))
    else:
        results.append(("Poprawne hasło, brak tokenu CAPTCHA", f"odrzucone (HTTP {r.status_code})", "CAPTCHA"))

    _, r = try_login(base, args.user, args.password, DUMMY_TOKEN, honeypot="http://spam.example")
    if logged_in(r):
        results.append(("Poprawne hasło, wypełnione pole-pułapka", "ZALOGOWANO", "brak"))
    else:
        results.append(("Poprawne hasło, wypełnione pole-pułapka", f"odrzucone (HTTP {r.status_code})", "pole-pułapka"))

    session, r = try_login(base, args.user, args.password, DUMMY_TOKEN)
    if logged_in(r):
        url, csrf = get_csrf(session, base + "/haslo/")
        data = {"csrfmiddlewaretoken": csrf, "old_password": args.password,
                "new_password1": "nowe-haslo-bota-1", "new_password2": "nowe-haslo-bota-1"}
        r = session.post(url, data=data, allow_redirects=False)
        if r.status_code == 400:
            results.append(("Zmiana hasła bez tokenu CAPTCHA", "odrzucone (HTTP 400)", "CAPTCHA przy zmianie hasła"))
        else:
            results.append(("Zmiana hasła bez tokenu CAPTCHA", f"PRZYJĘTE (HTTP {r.status_code})", "brak"))
    else:
        results.append(("Zmiana hasła bez tokenu CAPTCHA", "bot nie zalogował się", "CAPTCHA przy logowaniu"))

    outcome = ("brak blokady po " + str(args.attempts) + " próbach", "brak")
    for attempt in range(1, args.attempts + 1):
        _, r = try_login(base, args.target, f"zgadywane-haslo-{attempt}", DUMMY_TOKEN)
        message = error_text(r)
        print(f"  próba {attempt}: HTTP {r.status_code} {message}")
        if logged_in(r):
            outcome = (f"ZALOGOWANO w próbie {attempt}", "brak")
            break
        if "zablokowane" in message:
            outcome = (f"konto zablokowane w próbie {attempt}", "limit prób")
            break
        if r.status_code == 400:
            outcome = ("próby odrzucone przez CAPTCHA", "CAPTCHA")
    results.append((f"Brute force na konto {args.target}", *outcome))

    _, r = try_login(base, args.trap, "admin123", DUMMY_TOKEN)
    results.append((f"Logowanie na konto {args.trap}", f"odrzucone, {error_text(r) or r.status_code}", "konto-pułapka (alert)"))

    print()
    print(f"{'Atak':<42} {'Wynik':<38} Zabezpieczenie")
    print("-" * 110)
    for attack, result, protection in results:
        print(f"{attack:<42} {result:<38} {protection}")


if __name__ == "__main__":
    main()