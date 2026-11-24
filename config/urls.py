from django.urls import path

from accounts import views

urlpatterns = [
    path("", views.home, name="home"),
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),
    path("haslo/", views.change_password, name="change_password"),
    path("haslo/nowe/", views.force_change, name="force_change"),
    path("notatki/", views.notes, name="notes"),
    path("uzytkownicy/", views.users, name="users"),
    path("uzytkownicy/nowy/", views.user_form, name="user_add"),
    path("uzytkownicy/<int:pk>/", views.user_form, name="user_edit"),
    path("uzytkownicy/<int:pk>/<str:action>/", views.user_action, name="user_action"),
    path("ustawienia/", views.settings_view, name="settings"),
    path("dziennik/", views.log_view, name="logs"),
]
