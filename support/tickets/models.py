from django.db import models

# Create your models here.
import json

from django.db import models
from django.contrib.auth import get_user_model

# User = get_user_model()
from django.utils import timezone
from users.models import User


class Ticket(models.Model):
    STATUS_SOLVED = 'solved'
    STATUS_UNSOLVED = 'unsolved'
    STATUS_FROZEN = 'frozen'
    STATUS_CHOICES = (
        (STATUS_SOLVED, 'Тикет решен'),
        (STATUS_UNSOLVED, 'Тикет не решен'),
        (STATUS_FROZEN, 'Тикет заморожен'),
    )

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    created = models.DateTimeField(auto_now_add=True)
    topic = models.CharField(max_length=200, db_index=True)
    description = models.TextField(blank=True)
    status = models.CharField(max_length=100, verbose_name='Статус тикета', choices=STATUS_CHOICES,
                              default=STATUS_UNSOLVED)

    class Meta:
        ordering = ('created',)
        verbose_name = 'ticket'
        verbose_name_plural = 'tickets'

    def __str__(self):
        return self.topic


class TicketResponse(models.Model):
    data = models.DateTimeField(auto_now_add=True)
    response = models.TextField(blank=True)
    ticket = models.ForeignKey(Ticket, on_delete=models.CASCADE)

    class Meta:
        ordering = ('data',)
        verbose_name = 'response'
        verbose_name_plural = 'responses'
