from uuid import uuid4
from django.core import mail
from django.shortcuts import get_object_or_404
from django.contrib.auth.hashers import check_password
from rest_framework import status
from rest_framework.test import APIClient, APIRequestFactory, APITestCase
from .views import ResetPasswordView
from .models import User, PasswordResetToken


class AbstractAuthenticationTest(APITestCase):
    client = APIClient()
    username = "test"
    first_name = "test"
    last_name = "test"
    email = "test@test.com"
    password = "this_is_a_strong_password!"
    invalid = 'invalid'

    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(
            username=cls.username,
            email=cls.email,
            first_name='test',
            last_name='test',
            password=cls.password
        )


class LoginAuthenticationTest(AbstractAuthenticationTest):
    def test_get_login_page_returns_200(self):
        response = self.client.get('/auth/login/', format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_authenticated_get_login_page_returns_200(self):
        self.client.force_authenticate(self.user)
        response = self.client.get('/auth/login/', format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_username_invalid_returns_422(self):
        response = self.client.post('/auth/login/', {
            'username_or_email': "invalid",
            'password': self.password
        }, format='json')
        self.assertEqual(response.data['errors'], 'Invalid credentials')
        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)

    def test_email_invalid_returns_422(self):
        response = self.client.post('/auth/login/', {
            'username_or_email': "email@invalid.com",
            'password': self.password
        }, format='json')
        self.assertEqual(response.data['errors'], 'Invalid credentials')
        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)

    def test_password_invalid_returns_422(self):
        response = self.client.post('/auth/login/', {
            'username_or_email': self.username,
            'password': "invalid"
        }, format='json')
        self.assertEqual(response.data['errors'], 'Invalid credentials')
        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)

    def test_username_and_password_valid_returns_302(self):
        response = self.client.post('/auth/login/', {
            'username_or_email': self.username,
            'password': self.password
        }, format='json')
        self.assertEqual(response.status_code, status.HTTP_302_FOUND)

    def test_email_and_password_valid_returns_302(self):
        response = self.client.post('/auth/login/', {
            'username_or_email': self.email,
            'password': self.password
        }, format='json')
        self.assertEqual(response.status_code, status.HTTP_302_FOUND)

    def test_already_authenticated_credentials_valid_returns_302(self):
        self.client.force_authenticate(self.user)
        response = self.client.post('/auth/login/', {
            'username_or_email': self.email,
            'password': self.password
        }, format='json')
        self.assertEqual(response.status_code, status.HTTP_302_FOUND)


class CreateUserAuthenticationTest(AbstractAuthenticationTest):
    new_username = 'new_username'
    new_email = 'new_email@test.com'

    def test_authenticated_get_create_account_page_returns_403(self):
        self.client.force_authenticate(self.user)
        response = self.client.get('/auth/create-account/', format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_get_create_account_page_returns_200(self):
        response = self.client.get('/auth/create-account/', format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_email_invalid_returns_400(self):
        response = self.client.post('/auth/create-account/', {
            'username': self.new_username,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'email': self.invalid,
            'password': self.password,
            'confirm_password': self.password
        }, format='json')
        self.assertEqual(response.data['errors'], 'Enter a valid email address.')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_missing_first_name_field_returns_400(self):
        response = self.client.post('/auth/create-account/', {
            'username': self.new_username,
            'last_name': self.last_name,
            'email': self.new_email,
            'password': self.password,
            'confirm_password': self.password
        }, format='json')
        self.assertEqual(response.data['errors'], 'Please enter your first and last name.')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_missing_last_name_field_returns_400(self):
        response = self.client.post('/auth/create-account/', {
            'username': self.new_username,
            'first_name': self.first_name,
            'email': self.new_email,
            'password': self.password,
            'confirm_password': self.password
        }, format='json')
        self.assertEqual(response.data['errors'], 'Please enter your first and last name.')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_passwords_dont_match_returns_400(self):
        response = self.client.post('/auth/create-account/', {
            'username': self.new_username,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'email': self.new_email,
            'password': self.password,
            'confirm_password': self.invalid
        }, format='json')
        self.assertEqual(response.data['errors'], 'Passwords don\'t match.')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_password_too_short_returns_400(self):
        response = self.client.post('/auth/create-account/', {
            'username': self.new_username,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'email': self.new_email,
            'password': self.invalid,
            'confirm_password': self.invalid
        }, format='json')
        self.assertEqual(response.data['errors'], 'Password is too weak.')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_email_already_associated_with_account_returns_400(self):
        response = self.client.post('/auth/create-account/', {
            'username': self.new_username,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'email': self.email,
            'password': self.password,
            'confirm_password': self.password
        }, format='json')
        self.assertEqual(response.data['errors'], 'user with this email already exists.')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_username_already_associated_with_account_returns_400(self):
        response = self.client.post('/auth/create-account/', {
            'username': self.username,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'email': self.new_email,
            'password': self.password,
            'confirm_password': self.password
        }, format='json')
        self.assertEqual(response.data['errors'], 'A user with that username already exists.')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_already_authenticated_valid_credentials_returns_403(self):
        self.client.force_authenticate(self.user)
        response = self.client.post('/auth/create-account/', {
            'username': self.new_username,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'email': self.new_email,
            'password': self.password,
            'confirm_password': self.password
        }, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_valid_data_and_object_created_returns_302(self):
        response = self.client.post('/auth/create-account/', {
            'username': self.new_username,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'email': self.new_email,
            'password': self.password,
            'confirm_password': self.password
        }, format='json')
        self.assertNotEquals(get_object_or_404(User, username=self.new_username), status.HTTP_404_NOT_FOUND)
        self.assertEqual(response.status_code, status.HTTP_302_FOUND)


class LogoutTest(AbstractAuthenticationTest):
    def test_get_logout_page_if_not_authenticated_returns_302(self):
        response = self.client.get('/auth/logout/', format='json')
        self.assertEqual(response.status_code, status.HTTP_302_FOUND)

    def test_get_logout_page_if_authenticated_returns_200(self):
        self.client.force_authenticate(self.user)
        response = self.client.get('/auth/logout/', format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_not_authenticated_returns_302(self):
        response = self.client.post('/auth/logout/', format='json')
        self.assertEqual(response.status_code, status.HTTP_302_FOUND)

    def test_authenticated_returns_200(self):
        self.client.force_authenticate(self.user)
        response = self.client.get('/auth/logout/', format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)


class PasswordResetEnterEMailTest(AbstractAuthenticationTest):
    def test_get_password_reset_page_returns_200(self):
        response = self.client.get('/auth/reset-password/', format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_authenticated_get_password_reset_page_returns_200(self):
        self.client.force_authenticate(self.user)
        self.test_get_password_reset_page_returns_200()

    def test_invalid_email_returns_400(self):
        response = self.client.post('/auth/reset-password/', {
            'email': 'fake@email.com',
        }, format='json')
        self.assertEqual(response.data['errors'], 'No account with this E-Mail exists')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_valid_credentials_and_email_sent_returns_200(self):
        response = self.client.post('/auth/reset-password/', {
            'email': self.email
        }, format='json')
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to[0], self.email)
        self.assertEqual(len(PasswordResetToken.objects.all()), 1)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_authenticated_valid_credentials_email_sent_returns_200(self):
        self.client.force_authenticate(self.user)
        self.test_valid_credentials_and_email_sent_returns_200()


class AbstractPasswordResetTest(AbstractAuthenticationTest):
    factory = APIRequestFactory()

    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.token = PasswordResetToken.objects.create(
            token=uuid4(),
            user=cls.user
        )


class PasswordResetEnterPasswordTest(AbstractPasswordResetTest):
    def test_get_non_existent_password_reset_uuid_page_returns_404(self):
        response = self.client.get(f'/auth/reset-password/{uuid4()}/', format='json')
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_get_password_reset_uuid_page_returns_200(self):
        response = self.client.get(f'/auth/reset-password/{self.token.token}/', format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_authenticated_get_password_reset_uuid_page_returns_200(self):
        self.client.force_authenticate(self.user)
        self.test_get_password_reset_uuid_page_returns_200()

    def test_passwords_dont_match_returns_400(self):
        request = self.factory.patch(f'/auth/reset-password/{self.token.token}/', data={
            'password': self.password,
            'confirm_password': self.invalid
        }, format='json')
        response = ResetPasswordView.as_view()(request, self.token.token)
        self.assertEqual(response.data['errors'], 'Passwords don\'t match.')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_password_invalid_returns_400(self):
        request = self.factory.patch(f'/auth/reset-password/{self.token.token}/', data={
            'password': self.invalid,
            'confirm_password': self.invalid
        }, format='json')
        response = ResetPasswordView.as_view()(request, self.token.token)
        self.assertEqual(response.data['errors'], 'Password is too weak.')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_password_valid_returns_200(self):
        new_password = 'this_is_another_strong_password!'
        request = self.factory.patch(f'/auth/reset-password/{self.token.token}/', data={
            'password': new_password,
            'confirm_password': new_password
        })
        response = ResetPasswordView.as_view()(request, self.token.token)
        self.assertTrue(check_password(new_password, User.objects.get(id=self.token.user.id).password))
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_authenticated_password_valid_returns_200(self):
        self.client.force_authenticate(self.user)
        self.test_password_valid_returns_200()


class DeletePasswordResetTokenTest(AbstractPasswordResetTest):
    def test_get_invalid_token_delete_page_returns_404(self):
        response = self.client.get(f'/auth/reset-password/{uuid4()}/not-you/', format='json')
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_get_token_delete_page_returns_200(self):
        response = self.client.get(f'/auth/reset-password/{self.token.token}/not-you/', format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_authenticated_and_get_token_delete_page_returns_200(self):
        self.client.force_authenticate(self.user)
        self.test_get_token_delete_page_returns_200()

    def test_confirm_returns_200(self):
        response = self.client.delete(f'/auth/reset-password/{self.token.token}/not-you/', format='json')
        self.assertFalse(PasswordResetToken.objects.filter(token=self.token.token))
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_authenticated_confirm_returns_200(self):
        self.client.force_authenticate(self.user)
        self.test_confirm_returns_200()
