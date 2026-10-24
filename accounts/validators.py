import hashlib

import requests
from django.contrib.auth.hashers import check_password
from django.core.exceptions import ValidationError

from .models import PasswordHistory, SecuritySettings


def pwned_count(password):
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    response = requests.get(
        f"https://api.pwnedpasswords.com/range/{sha1[:5]}",
        headers={"Add-Padding": "true"},
        timeout=5,
    )
    response.raise_for_status()
    for line in response.text.splitlines():
        suffix, count = line.split(":")
        if suffix == sha1[5:]:
            return int(count)
    return 0


class PasswordPolicyValidator:
    def validate(self, password, user=None):
        settings = SecuritySettings.get()
        if len(password) < settings.min_length:
            raise ValidationError(f"Hasło musi mieć co najmniej {settings.min_length} znaków.")
        if user and user.pk and any(check_password(password, h.password) for h in user.history.all()[:5]):
            raise ValidationError("Hasło musi różnić się od 5 poprzednich haseł.")
        if settings.hibp_enabled:
            try:
                count = pwned_count(password)
            except requests.RequestException:
                raise ValidationError("Nie udało się sprawdzić hasła w bazie wycieków.")
            if count:
                raise ValidationError(f"Hasło wystąpiło w wyciekach danych ({count} razy).")

    def password_changed(self, password, user=None):
        PasswordHistory.objects.create(user=user, password=user.password)

    def get_help_text(self):
        return f"Co najmniej {SecuritySettings.get().min_length} znaków, inne niż 5 poprzednich haseł."
