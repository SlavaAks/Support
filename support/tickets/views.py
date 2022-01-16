from rest_framework import serializers

from support.settings import status_ticket
# Create your views here.

# from .utils import check_object_permissions
# Create your views here.
from rest_framework.views import APIView
from rest_framework.exceptions import APIException
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from .permissions import IsAuthor

from rest_framework import status
from rest_framework.response import Response

from .serializers import TicketSerializer, ResponseSerializer
from .models import *
from .task import sleepy,send_email_task_after_response,send_mail,send_email_task_befor_response

class APIUserTickets(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        serializer = TicketSerializer(Ticket.objects.filter(user=request.user), many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        serializer = TicketSerializer(data=request.data)
        if serializer.is_valid():
            serializer.create(request)
            send_email_task_befor_response.delay(request.user.email)

            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ViewTickets(APIView):
    permission_classes = [IsAdminUser]

    def get(self, request):
        tickets = Ticket.objects.all()
        serializer = TicketSerializer(tickets, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class APISupportTicket(APIView):
    permission_classes = [IsAdminUser]

    def post(self, request, ticket_id):

        serializer = ResponseSerializer(data=request.data)
        if serializer.is_valid():
            serializer.add_response_to_ticket(ticket_id)
            send_email_task_after_response.delay(request.user.email)
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, ticket_id):
        ticket = TicketSerializer.change_status(request, ticket_id)
        serializer=TicketSerializer(ticket)
        return Response(serializer.data,status=status.HTTP_200_OK)

class ViewResponse(APIView):
    permission_classes = [IsAuthenticated, IsAuthor]

    def get(self, request, ticket_id):
        resp = ResponseSerializer.obtain_response(ticket_id)
        serializer = ResponseSerializer(resp)
        return Response(serializer.data, status=status.HTTP_200_OK)
