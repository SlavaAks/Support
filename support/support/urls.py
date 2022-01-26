from django.contrib import admin
from django.urls import path
from rest_framework_jwt.views import *

from tickets.views import *
from users.views import *

urlpatterns = [
    path('admin/', admin.site.urls),
    path('user_tickets',APIUserTickets.as_view()),
    path('tickets',ViewTickets.as_view()),
    path('support_response/<int:ticket_id>',APISupportTicket.as_view()),
    path('ticket_response/<int:ticket_id>',ViewResponse.as_view()),
    path('log_in', obtain_jwt_token),
    path('registration', CreateUserAPIView.as_view())
]
