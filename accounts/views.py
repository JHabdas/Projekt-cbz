import json

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth.forms import PasswordChangeForm, SetPasswordForm
from django.core.exceptions import PermissionDenied
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from . import audit
from .audit import log_event
from .forms import LoginForm, NoteForm, SettingsForm, UserForm
from .models import Note, SecuritySettings, User
from .security import bot_detected, canary_alert, turnstile_ok

GENERIC_ERROR = "Login lub hasło niepoprawne"
CAPTCHA_ERROR = "Weryfikacja CAPTCHA nie powiodła się. Spróbuj ponownie."

def lock_message(user):
    minutes, seconds = divmod(int(user.lock_remaining().total_seconds()), 60)
    return f"Konto zablokowane. Pozostały czas blokady: {minutes} min {seconds} s."


def login_view(request):
    form = LoginForm(request.POST or None)
    error = None
    status = 200
    if request.method == "POST":
        username = request.POST.get("username", "")
        if request.POST.get("website"):
            bot_detected(request)
            error = GENERIC_ERROR
            log_event(request, "LOGOWANIE_NIEUDANE", "Wypełnione pole-pułapka (bot)", False, username)
        elif username == settings.TRAP_USERNAME:
            canary_alert(request, username)
            error = GENERIC_ERROR
        elif not turnstile_ok(request):
            error = CAPTCHA_ERROR
            status = 400
            log_event(request, "LOGOWANIE_NIEUDANE", "Brak lub błędny token CAPTCHA", False, username)
        elif form.is_valid():
            user = User.objects.filter(username=username).first()
            if user and user.lock_remaining():
                error = lock_message(user)
                log_event(request, "LOGOWANIE_NIEUDANE", "Próba logowania na zablokowane konto", False, username)
            else:
                authenticated = authenticate(request, **form.cleaned_data)
                if authenticated is None:
                    error = GENERIC_ERROR
                    log_event(request, "LOGOWANIE_NIEUDANE", "Błędny login lub hasło", False, username)
                    if user:
                        user.register_failed_login()
                        if user.lock_remaining():
                            error = lock_message(user)
                            log_event(request, "BLOKADA_KONTA", f"Konto zablokowane na {settings.LOCKOUT_MINUTES} min", True, username)
                elif authenticated.otp_expired():
                    error = "Hasło jednorazowe wygasło. Poproś administratora o nowe."
                    log_event(request, "LOGOWANIE_NIEUDANE", "Hasło jednorazowe wygasło", False, username)
                else:
                    authenticated.reset_failed_logins()
                    login(request, authenticated)
                    log_event(request, "LOGOWANIE", "Zalogowano", True)
                    return redirect("home")
    context = {"form": form, "error": error, "captcha_site_key": settings.TURNSTILE_SITE_KEY}
    return render(request, "login.html", context, status=status)

@require_POST
def logout_view(request):
    log_event(request, "WYLOGOWANIE", "Wylogowano", True)
    logout(request)
    messages.info(request, "Wylogowano.")
    return redirect("login")


@login_required
def home(request):
    return render(request, "home.html")


def save_password(request, form):
    form.user.must_change_password = False
    form.user.otp_expires_at = None
    form.save()
    update_session_auth_hash(request, form.user)
    messages.success(request, "Hasło zostało zmienione.")
    return redirect("home")


def password_form(request, form, title):
    status = 200
    if request.method == "POST":
        if not turnstile_ok(request):
            messages.error(request, CAPTCHA_ERROR)
            status = 400
            log_event(request, "ZMIANA_HASLA", f"{title}: brak lub błędny token CAPTCHA", False)
        elif form.is_valid():
            log_event(request, "ZMIANA_HASLA", title, True)
            return save_password(request, form)
        else:
            log_event(request, "ZMIANA_HASLA", f"{title}: hasło odrzucone przez walidację", False)
    context = {"form": form, "title": title, "captcha_site_key": settings.TURNSTILE_SITE_KEY}
    return render(request, "form.html", context, status=status)


@login_required
def force_change(request):
    return password_form(request, SetPasswordForm(request.user, request.POST or None), "Ustaw nowe hasło")


@login_required
def change_password(request):
    return password_form(request, PasswordChangeForm(request.user, request.POST or None), "Zmiana hasła")

@login_required
@permission_required("accounts.view_note", raise_exception=True)
def notes(request):
    form = NoteForm(request.POST or None)
    if request.method == "POST":
        if not request.user.has_perm("accounts.add_note"):
            raise PermissionDenied
        if form.is_valid():
            form.instance.author = request.user
            form.save()
            return redirect("notes")
    return render(request, "notes.html", {"notes": Note.objects.all(), "form": form})

@login_required
@permission_required("accounts.change_user", raise_exception=True)
def user_form(request, pk=None):
    user = get_object_or_404(User, pk=pk) if pk else None
    old_role = user.role if user else None
    form = UserForm(request.POST or None, instance=user)
    if form.is_valid():
        saved = form.save()
        if user is None:
            log_event(request, "UZYTKOWNIK_DODANY", f"Dodano konto {saved.username} z rolą {saved.role}", True)
            return render(request, "otp.html", {"target": saved, "otp": saved.set_one_time_password()})
        if saved.role != old_role:
            log_event(request, "ZMIANA_ROLI", f"Konto {saved.username}: {old_role} -> {saved.role}", True)
        else:
            log_event(request, "UZYTKOWNIK_ZMIENIONY", f"Zmieniono dane konta {saved.username}", True)
        return redirect("users")
    return render(request, "form.html", {"form": form, "title": "Użytkownik"})


@login_required
@permission_required("accounts.change_user", raise_exception=True)
def users(request):
    return render(request, "users.html", {"users": User.objects.order_by("username")})


@login_required
@permission_required("accounts.change_user", raise_exception=True)
def user_form(request, pk=None):
    user = get_object_or_404(User, pk=pk) if pk else None
    form = UserForm(request.POST or None, instance=user)
    if form.is_valid():
        saved = form.save()
        if user is None:
            return render(request, "otp.html", {"target": saved, "otp": saved.set_one_time_password()})
        return redirect("users")
    return render(request, "form.html", {"form": form, "title": "Użytkownik"})


@require_POST
@login_required
@permission_required("accounts.change_user", raise_exception=True)
def user_action(request, pk, action):
    user = get_object_or_404(User, pk=pk)
    if action == "reset":
        log_event(request, "RESET_HASLA", f"Nowe hasło jednorazowe dla {user.username}", True)
        return render(request, "otp.html", {"target": user, "otp": user.set_one_time_password()})
    if user.username == "ADMIN" or user == request.user:
        messages.error(request, "Tego konta nie można zablokować ani usunąć.")
    elif action == "block":
        user.is_active = not user.is_active
        user.save()
        log_event(request, "UZYTKOWNIK_ODBLOKOWANY" if user.is_active else "UZYTKOWNIK_ZABLOKOWANY", f"Konto {user.username}", True)
    elif action == "delete":
        log_event(request, "UZYTKOWNIK_USUNIETY", f"Usunięto konto {user.username}", True)
        user.delete()
    return redirect("users")


@login_required
@permission_required("accounts.change_securitysettings", raise_exception=True)
def settings_view(request):
    form = SettingsForm(request.POST or None, instance=SecuritySettings.get())
    if form.is_valid():
        form.save()
        changes = ", ".join(f"{name}={form.cleaned_data[name]}" for name in form.changed_data)
        log_event(request, "ZMIANA_USTAWIEN", changes or "Bez zmian", True)
        messages.success(request, "Zapisano ustawienia.")
    return render(request, "form.html", {"form": form, "title": "Ustawienia bezpieczeństwa"})

@login_required
@permission_required("accounts.change_securitysettings", raise_exception=True)
def log_view(request):
    if request.method == "POST":
        intact = audit.verify()
        if intact:
            messages.success(request, "Dziennik nienaruszony: skrót SHA-256 się zgadza.")
            log_event(request, "WERYFIKACJA_DZIENNIKA", "Dziennik nienaruszony", True)
        else:
            messages.error(request, "Wykryto ingerencję w dziennik: skrót SHA-256 się nie zgadza.")
            audit.save_alert("Naruszona integralność dziennika", request.user.username, "Skrót SHA-256 pliku dziennika nie zgadza się z zapisanym")
            log_event(request, "WERYFIKACJA_DZIENNIKA", "Wykryto ingerencję w dziennik", False)
        return redirect("logs")
    entries = audit.read_json(audit.LOG_FILE)
    filters = {name: request.GET.get(name, "") for name in ["user", "action", "date_from", "date_to"]}
    rows = audit.filter_entries(entries or [], **filters)
    if "export" in request.GET:
        log_event(request, "EKSPORT_DZIENNIKA", f"Wyeksportowano {len(rows)} wpisów", True)
        response = HttpResponse(json.dumps(rows, ensure_ascii=False, indent=2), content_type="application/json")
        response["Content-Disposition"] = 'attachment; filename="dziennik_eksport.json"'
        return response
    context = {
        "rows": rows,
        "filters": filters,
        "actions": audit.ACTIONS,
        "broken": entries is None,
        "query": request.GET.urlencode(),
    }
    return render(request, "logs.html", context)