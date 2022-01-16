from django.contrib import admin

# Register your models here.
from django.contrib import admin
from .models import *


@admin.register(Ticket)
class TicketAdmin(admin.ModelAdmin):
    list_display = ['topic', 'description', 'status', 'created']
