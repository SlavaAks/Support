import pytest

from importlib import import_module
from django import VERSION as DJANGO_VERSION
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import AnonymousUser
from rest_framework.test import APIClient, APIRequestFactory
import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'support.settings')
import django
django.setup()

@pytest.fixture
def session():
    engine = import_module(settings.SESSION_ENGINE)
    session = engine.SessionStore()
    session.create()
    return session


@pytest.fixture
def api_client():
    api_client = APIClient()
    return api_client

