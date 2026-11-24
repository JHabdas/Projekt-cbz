import time
from django.core.exceptions import PermissionDenied
from .audit import log_event

from django.contrib import messages
from django.contrib.auth import logout
from django.shortcuts import redirect
from django.urls import reverse

from .models import SecuritySettings


class AccountMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        user = request.user
        if user.is_authenticated:
            timeout = SecuritySettings.get().session_minutes * 60
            last = request.session.get("last_activity")
            if last and time.time() - last > timeout:
                log_event(request, "WYLOGOWANIE", "Wylogowano z powodu bezczynności", True)
                logout(request)
                messages.info(request, "Wylogowano z powodu bezczynności.")
                return redirect("login")
            request.session["last_activity"] = time.time()
            request.session_timeout = timeout
            allowed = [reverse("force_change"), reverse("logout")]
            if (user.must_change_password or user.password_expired()) and request.path not in allowed:
                return redirect("force_change")
        return self.get_response(request)

class AccessDeniedMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        return self.get_response(request)

    def process_exception(self, request, exception):
        if isinstance(exception, PermissionDenied):
            log_event(request, "ODMOWA_DOSTEPU", f"Brak uprawnień do {request.path}", False)
        return None