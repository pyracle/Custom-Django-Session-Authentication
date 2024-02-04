from rest_framework.request import Request
from celery import shared_task
from templated_mail.mail import BaseEmailMessage


@shared_task
def send_password_reset_email(
        request: Request,
        email_address: str,
        password_reset_url: str):
    BaseEmailMessage(
        request,
        {'url': password_reset_url},
        'authentication/password_reset_email.html'
    ).send([email_address])
