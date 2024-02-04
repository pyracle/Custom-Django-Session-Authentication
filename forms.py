from django import forms
from django.contrib.auth.password_validation import validate_password


class PasswordField(forms.CharField):
    def validate(self, value):
        super().validate(value)
        validate_password(value)


def char_input(placeholder: str = "Username"):
    return forms.CharField(
        max_length=100,
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "style": "width: 100%; border: none; outline: none",
                "autocomplete": "off",
                "placeholder": placeholder,
            }
        ),
    )


def email_input():
    return forms.EmailField(
        max_length=100,
        widget=forms.EmailInput(
            attrs={
                "class": "form-control",
                "style": "width: 100%; border: none; outline: none",
                "autocomplete": "off",
                "placeholder": "E-Mail",
            }
        ),
    )


def password_input(placeholder: str = "Password", field=PasswordField):
    return field(
        max_length=100,
        widget=forms.PasswordInput(
            attrs={
                "class": "form-control",
                "style": "width: 100%; border: none; outline: none",
                "autocomplete": "off",
                "placeholder": placeholder,
            }
        ),
    )


class UserLoginForm(forms.Form):
    username_or_email = char_input("Username or E-Mail")
    password = password_input(field=forms.CharField)


class CreateUserForm(forms.Form):
    username = char_input()
    first_name = char_input("First Name")
    last_name = char_input("Last Name")
    email = email_input()
    password = password_input("Set Password")
    confirm_password = password_input("Confirm Password")


class ResetPasswordEMailForm(forms.Form):
    email = email_input()


class ResetPasswordForm(forms.Form):
    password = password_input("New Password")
    confirm_password = password_input("Confirm Password")
