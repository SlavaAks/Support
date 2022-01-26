import os
from importlib import import_module

import pytest
from django.conf import settings
from rest_framework.test import APIClient

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

