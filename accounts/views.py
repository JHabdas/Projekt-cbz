from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth.forms import PasswordChangeForm, SetPasswordForm
from django.core.exceptions import PermissionDenied
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

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
        elif username == settings.TRAP_USERNAME:
            canary_alert(request, username)
            error = GENERIC_ERROR
        elif not turnstile_ok(request):
            error = CAPTCHA_ERROR
            status = 400
        elif form.is_valid():
            user = User.objects.filter(username=username).first()
            if user and user.lock_remaining():
                error = lock_message(user)
            else:
                authenticated = authenticate(request, **form.cleaned_data)
                if authenticated is None:
                    error = GENERIC_ERROR
                    if user:
                        user.register_failed_login()
                        if user.lock_remaining():
                            error = lock_message(user)
                elif authenticated.otp_expired():
                    error = "Hasło jednorazowe wygasło. Poproś administratora o nowe."
                else:
                    authenticated.reset_failed_logins()
                    login(request, authenticated)
                    return redirect("home")
    context = {"form": form, "error": error, "captcha_site_key": settings.TURNSTILE_SITE_KEY}
    return render(request, "login.html", context, status=status)

@require_POST
def logout_view(request):
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
        elif form.is_valid():
            return save_password(request, form)
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
        return render(request, "otp.html", {"target": user, "otp": user.set_one_time_password()})
    if user.username == "ADMIN" or user == request.user:
        messages.error(request, "Tego konta nie można zablokować ani usunąć.")
    elif action == "block":
        user.is_active = not user.is_active
        user.save()
    elif action == "delete":
        user.delete()
    return redirect("users")


@login_required
@permission_required("accounts.change_securitysettings", raise_exception=True)
def settings_view(request):
    form = SettingsForm(request.POST or None, instance=SecuritySettings.get())
    if form.is_valid():
        form.save()
        messages.success(request, "Zapisano ustawienia.")
    return render(request, "form.html", {"form": form, "title": "Ustawienia bezpieczeństwa"})
