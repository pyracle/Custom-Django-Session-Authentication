from typing import Callable
from django.shortcuts import redirect
from django.core.exceptions import PermissionDenied
from rest_framework.request import Request


def redirect_login(func: Callable):
    def inner(*args, **kwargs):
        request: Request = args[1]
        if request.user.is_anonymous:
            return redirect('/auth/login/')
        return func(*args, **kwargs)
    return inner


def check_authenticated(func: Callable):
    def inner(*args, **kwargs):
        request: Request = args[1]
        if request.user.is_authenticated:
            raise PermissionDenied()
        return func(*args, **kwargs)
    return inner
