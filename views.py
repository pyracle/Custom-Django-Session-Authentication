from re import sub
from uuid import uuid4
from django.http import Http404
from django.conf import settings
from django.db import transaction
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.shortcuts import (
    redirect,
    get_object_or_404
)
from django.contrib.auth import (
    authenticate,
    login,
    logout
)
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework.renderers import TemplateHTMLRenderer
from .tasks import send_password_reset_email
from .decorators import (
    redirect_login,
    check_authenticated
)
from .models import (
    User,
    PasswordResetToken
)
from .serializers import (
    CreateUserSerializer,
    CreatePasswordResetTokenSerializer,
    UpdateUserSerializer
)
from .forms import (
    ResetPasswordForm,
    UserLoginForm,
    CreateUserForm,
    ResetPasswordEMailForm
)


class AbstractAuthenticationView(APIView):
    permission_classes = [AllowAny]
    renderer_classes = [TemplateHTMLRenderer]

    def get(self, request: Request):
        try:
            context_data = {"form": self.form}
        except AttributeError:
            context_data = {}
        return Response(context_data, status=status.HTTP_200_OK)


class LoginView(AbstractAuthenticationView):
    template_name = "authentication/login.html"
    form = UserLoginForm()

    def post(self, request: Request):
        username_or_email, password = request.data["username_or_email"], request.data["password"]

        try:
            validate_email(username_or_email)
            user = authenticate(
                request,
                email=username_or_email,
                password=password
            )
        except ValidationError:
            user = authenticate(
                request,
                username=username_or_email,
                password=password
            )

        if isinstance(user, User):
            login(request, user)
            if settings.ADMIN_URL in request.get_full_path():
                return redirect(settings.ADMIN_URL)
            return redirect(settings.LOGIN_REDIRECT_URL)

        return Response(
            {"form": self.form, "errors": "Invalid credentials"},
            status=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )


class LogoutView(AbstractAuthenticationView):
    template_name = "authentication/logout.html"

    @redirect_login
    def get(self, request: Request):
        return Response(status=status.HTTP_200_OK)

    @redirect_login
    def post(self, request: Request):
        logout(request)
        return redirect(settings.LOGOUT_REDIRECT_URL)


class CreateUserView(AbstractAuthenticationView):
    template_name = "authentication/create_user.html"
    form = CreateUserForm()

    @check_authenticated
    def get(self, request: Request):
        return super().get(request)

    @check_authenticated
    def post(self, request: Request):
        serializer = CreateUserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            user = authenticate(
                request,
                email=request.data["email"],
                password=request.data["password"],
            )
            login(request, user)
            return redirect(settings.LOGIN_REDIRECT_URL)
        return Response(
            {
                "errors": str(list(serializer.errors.values())[0][0]),
                "form": self.form,
            },
            status=status.HTTP_400_BAD_REQUEST,
        )


class ResetPasswordEnterEMailView(AbstractAuthenticationView):
    template_name = "authentication/reset_password_email_form.html"
    form = ResetPasswordEMailForm()

    def post(self, request: Request):
        email_address = request.data["email"]
        user = User.objects.filter(email=email_address)
        
        if not user:
            return Response(
                {"errors": "No account with this E-Mail exists", "form": self.form},
                status=status.HTTP_400_BAD_REQUEST,
            )
        
        token = uuid4()
        homepage_url = sub(request.get_full_path(), '/', request.build_absolute_uri())
        reset_url = (
            f"{homepage_url}auth/reset-password/{token}/"
        )
        send_password_reset_email(request, email_address, reset_url)
        serializer = CreatePasswordResetTokenSerializer(
            data={"token": token, "user": user[0].id}
        )
        if serializer.is_valid():
            serializer.save()
        return Response(
            {"h1": "E-Mail was sent successfully"}, status=status.HTTP_200_OK
        )


class AbstractPasswordResetView(AbstractAuthenticationView):
    def get(self, request: Request, token: str):
        if request.user:
            logout(request)
        if PasswordResetToken.objects.filter(token=token):
            return super().get(request)
        raise Http404


class ResetPasswordView(AbstractPasswordResetView):
    template_name = "authentication/reset_password.html"
    form = ResetPasswordForm()

    def patch(self, request: Request, token):
        token_obj = get_object_or_404(PasswordResetToken, token=token)
        data = {
            "username": token_obj.user.username,
            "password": request.data["password"],
            "confirm_password": request.data["confirm_password"]
        }
        serializer = UpdateUserSerializer(token_obj.user, data)

        if serializer.is_valid():
            with transaction.atomic():
                serializer.save()
                token_obj.delete()
            return Response(
                {"h1": "Password was reset successfully"}, status=status.HTTP_200_OK
            )
        return Response(
            {
                "errors": str(list(serializer.errors.values())[0][0]),
                "form": self.form,
            },
            status=status.HTTP_400_BAD_REQUEST,
        )


class RemovePasswordResetTokenView(AbstractPasswordResetView):
    template_name = "authentication/remove_password_reset_token.html"

    def delete(self, request: Request, token):
        token_obj = get_object_or_404(PasswordResetToken, token=token)
        token_obj.delete()
        return Response(
            {"h1": "Confirmation was successful"}, status=status.HTTP_200_OK
        )
