"""support URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from tickets.views import *
from users.views import *
from rest_framework_jwt.views import *
urlpatterns = [
    path('admin/', admin.site.urls),
    path('user_tickets',APIUserTickets.as_view()),
    path('tickets',ViewTickets.as_view()),
    path('support_response/<int:ticket_id>',APISupportTicket.as_view()),
    path('ticket_response/<int:ticket_id>',ViewResponse.as_view()),
    path('log_in', obtain_jwt_token),
    path('registration', CreateUserAPIView.as_view())
]
