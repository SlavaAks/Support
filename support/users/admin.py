from django.contrib import admin

# Register your models here.
from django.contrib import admin

# Register your models here.
from django.contrib import admin
from .models import *


@admin.register(User)
class TicketAdmin(admin.ModelAdmin):
    list_display = ['first_name', 'last_name','email','is_staff']
