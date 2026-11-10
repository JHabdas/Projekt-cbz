import logging

import requests
from django.conf import settings

logger = logging.getLogger("security")

TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"


def client_ip(request):
    return request.META.get("REMOTE_ADDR", "")


def turnstile_ok(request):
    token = request.POST.get("cf-turnstile-response", "")
    if not token:
        return False
    try:
        response = requests.post(
            TURNSTILE_VERIFY_URL,
            data={
                "secret": settings.TURNSTILE_SECRET_KEY,
                "response": token,
                "remoteip": client_ip(request),
            },
            timeout=5,
        )
        return response.json().get("success", False)
    except (requests.RequestException, ValueError):
        return False


def canary_alert(request, username):
    logger.warning("Konto-pułapka: próba logowania na '%s' z IP %s", username, client_ip(request))
    if settings.CANARY_LOGIN_URL:
        try:
            requests.get(settings.CANARY_LOGIN_URL, params={"ip": client_ip(request)}, timeout=5)
        except requests.RequestException:
            pass


def bot_detected(request):
    logger.warning("Pole-pułapka wypełnione: prawdopodobny bot z IP %s", client_ip(request))