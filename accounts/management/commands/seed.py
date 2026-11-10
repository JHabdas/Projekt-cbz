from django.conf import settings
from django.contrib.auth.models import Group, Permission
from django.core.management.base import BaseCommand

from accounts.models import User

ROLES = {
    "Administrator": ["change_user", "change_securitysettings"],
    "Pracownik": ["view_note", "add_note"],
    "Gość": ["view_note"],
}

USERS = [
    ("ADMIN", "Administrator"),
    ("jkowalski", "Pracownik"),
    ("anowak", "Pracownik"),
    ("pwisniewski", "Pracownik"),
    ("mwojcik", "Gość"),
    ("kkaminska", "Gość"),
    ("tlewandowski", "Gość"),
]


class Command(BaseCommand):
    def handle(self, *args, **options):
        for name, codenames in ROLES.items():
            group, _ = Group.objects.get_or_create(name=name)
            group.permissions.set(
                Permission.objects.filter(content_type__app_label="accounts", codename__in=codenames)
            )
        for username, role in USERS:
            if User.objects.filter(username=username).exists():
                continue
            user = User.objects.create(username=username)
            user.groups.add(Group.objects.get(name=role))
            self.stdout.write(f"{username:<14} {role:<14} {user.set_one_time_password()}")
        if not User.objects.filter(username=settings.TRAP_USERNAME).exists():
            trap = User(username=settings.TRAP_USERNAME, must_change_password=False)
            trap.set_unusable_password()
            trap.save()
            self.stdout.write(f"{settings.TRAP_USERNAME:<14} konto-pułapka")