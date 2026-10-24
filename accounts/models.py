from datetime import timedelta

from django.contrib.auth.models import AbstractUser
from django.core.validators import MinValueValidator
from django.db import models
from django.utils import timezone
from django.utils.crypto import get_random_string


class User(AbstractUser):
    must_change_password = models.BooleanField(default=True)
    otp_expires_at = models.DateTimeField(null=True, blank=True)

    @property
    def role(self):
        group = self.groups.first()
        return group.name if group else "-"

    def otp_expired(self):
        return self.otp_expires_at is not None and timezone.now() > self.otp_expires_at

    def password_expired(self):
        days = SecuritySettings.get().password_days
        last = self.history.first()
        return bool(days and last and timezone.now() > last.created_at + timedelta(days=days))

    def set_one_time_password(self):
        otp = get_random_string(14)
        self.set_password(otp)
        self.must_change_password = True
        self.otp_expires_at = timezone.now() + timedelta(hours=24)
        self.save()
        return otp


class PasswordHistory(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="history")
    password = models.CharField(max_length=128)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]


class SecuritySettings(models.Model):
    min_length = models.PositiveIntegerField(
        "Minimalna długość hasła", default=12, validators=[MinValueValidator(8)]
    )
    hibp_enabled = models.BooleanField("Sprawdzanie hasła w Have I Been Pwned", default=False)
    password_days = models.PositiveIntegerField("Ważność hasła w dniach (0 = bez limitu)", default=0)
    session_minutes = models.PositiveIntegerField(
        "Wylogowanie po bezczynności (minuty)", default=15, validators=[MinValueValidator(1)]
    )

    @classmethod
    def get(cls):
        return cls.objects.get_or_create(pk=1)[0]


class Note(models.Model):
    title = models.CharField("Treść", max_length=200)
    author = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
