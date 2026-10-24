from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth.forms import PasswordChangeForm, SetPasswordForm
from django.core.exceptions import PermissionDenied
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from .forms import LoginForm, NoteForm, SettingsForm, UserForm
from .models import Note, SecuritySettings, User


def login_view(request):
    form = LoginForm(request.POST or None)
    error = None
    if form.is_valid():
        user = authenticate(request, **form.cleaned_data)
        if user is None:
            error = "Login lub hasło niepoprawne"
        elif user.otp_expired():
            error = "Hasło jednorazowe wygasło. Poproś administratora o nowe."
        else:
            login(request, user)
            return redirect("home")
    return render(request, "login.html", {"form": form, "error": error})


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


@login_required
def force_change(request):
    form = SetPasswordForm(request.user, request.POST or None)
    if form.is_valid():
        return save_password(request, form)
    return render(request, "form.html", {"form": form, "title": "Ustaw nowe hasło"})


@login_required
def change_password(request):
    form = PasswordChangeForm(request.user, request.POST or None)
    if form.is_valid():
        return save_password(request, form)
    return render(request, "form.html", {"form": form, "title": "Zmiana hasła"})


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
