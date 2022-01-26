import pytest
from django.test import TestCase
from rest_framework_jwt.compat import get_user_model

from tickets.models import Ticket
from users.models import User

User = get_user_model()


@pytest.mark.django_db
class Test_action_with_model(TestCase):
    """JSON Web Token Authentication"""

    def setUp(self):
        self.username = 'jpueblo'
        self.email = 'jpueblo@example.com'
        self.user = User.objects.create_user(self.username, self.email)

    def test_create_user(self):
        self.assertEqual(User.objects.get_by_natural_key(username='jpueblo'), self.user)

    def test_ticket_create(self):
        self.topic = "uuurururururu"
        self.description = "uruuutuuiiirkkfkfkfkf"
        self.ticket = Ticket.objects.create(user=self.user, topic=self.topic, description=self.description)
        self.assertEqual(Ticket.objects.get(topic='uuurururururu'), self.ticket)
        self.assertEqual(Ticket.objects.get(topic='uuurururururu').status, 'unsolved')

