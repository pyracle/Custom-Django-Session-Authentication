from django.urls import path
from . import views


urlpatterns = [
    path("login/", views.LoginView.as_view()),
    path("logout/", views.LogoutView.as_view()),
    path("create-account/", views.CreateUserView.as_view()),
    path("reset-password/", views.ResetPasswordEnterEMailView.as_view()),
    path("reset-password/<uuid:token>/", views.ResetPasswordView.as_view()),
    path("reset-password/<uuid:token>/not-you/", views.RemovePasswordResetTokenView.as_view())
]
