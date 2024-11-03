from django.shortcuts import render
from django.contrib.auth.models import Group, User
from rest_framework.permissions import AllowAny
from rest_framework import permissions, viewsets, status
from rest_framework.response import Response
from rest_framework.views import APIView
from .serializers import GroupSerializer, UserSerializer, UserSerializateRegister

# Create your views here.

class UserViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows users to be viewed or edited.
    """
    queryset = User.objects.all().order_by('-date_joined')
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]


class GroupViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows groups to be viewed or edited.
    """
    queryset = Group.objects.all().order_by('name')
    serializer_class = GroupSerializer
    permission_classes = [permissions.IsAuthenticated]
    
class UserRegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializate = UserSerializateRegister(data=request.data)
        if serializate.is_valid():
            serializate.save()
            return Response(
                serializate.data,
                status=status.HTTP_201_CREATED
                )
        return Response(
            serializate.errors,
            status=status.HTTP_400_BAD_REQUEST
        )