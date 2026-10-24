from django import forms
from django.contrib.auth.models import Group

from .models import Note, SecuritySettings, User


class LoginForm(forms.Form):
    username = forms.CharField(label="Login")
    password = forms.CharField(label="Hasło", widget=forms.PasswordInput)


class UserForm(forms.ModelForm):
    role = forms.ModelChoiceField(Group.objects.all(), label="Rola")

    class Meta:
        model = User
        fields = ["username", "first_name", "last_name"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance.pk:
            self.fields["username"].disabled = True
            self.fields["role"].initial = self.instance.groups.first()
            if self.instance.username == "ADMIN":
                self.fields["role"].disabled = True

    def save(self):
        user = super().save()
        user.groups.set([self.cleaned_data["role"]])
        return user


class SettingsForm(forms.ModelForm):
    class Meta:
        model = SecuritySettings
        fields = "__all__"


class NoteForm(forms.ModelForm):
    class Meta:
        model = Note
        fields = ["title"]
