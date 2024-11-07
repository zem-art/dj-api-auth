from django.shortcuts import render, get_object_or_404
from django.contrib.auth.models import Group, User
from django.contrib.auth import authenticate
from rest_framework.permissions import AllowAny
from rest_framework import permissions, viewsets, status
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from rest_framework.views import APIView
from rest_framework.decorators import action
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
    permission_classes = [AllowAny] # Mengizinkan akses tanpa autentikasi

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

class UserViewSets(viewsets.ViewSet):
    permission_classes = []

    @action(detail=False, methods=['POST']) # DECORATOR
    def sign_up(self, request, *args, **kwargs):

        serializate = UserSerializateRegister(data=request.data)
        if serializate.is_valid():
            serializate.save()

            return Response({
                'title' : 'succeed',
                'message': 'successfully registered user',
                'data' : serializate.data,
                }, status=status.HTTP_201_CREATED)
        return Response({
                'title' : 'failed',
                'response' : serializate.errors,
                'message' : '',
            }, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['POST']) # DECORATOR
    def sign_in(self, request, *args, **kwargs):

        username = request.data['username']
        password = request.data['password']
        userAuth = authenticate(username=username, password=password)

        if userAuth:
            token, created = Token.objects.get_or_create(user = userAuth)
            findUsers = get_object_or_404(User, username=username)
            data_obj = {
                'username' : findUsers.username,
                'email' : findUsers.email,
                'first_name' : findUsers.first_name,
                'last_name' : findUsers.last_name,
            }
            
            return Response({
                'title' : 'succeed',
                'message': 'successfully logged in',
                'data' : {
                        'info_user' : data_obj,
                        'token' : token.key
                    },
                }, status=status.HTTP_200_OK)

        return Response({
                'title' : 'failed',
                'message': 'Make sure the username and password are correct and also we cannot find an account with that data.',
                'response' : userAuth,
            }, status=status.HTTP_400_BAD_REQUEST)
        
    @action(detail=False, methods=['GET']) # DECORATOR
    def profile(self, request, *args, **kwargs):
        auth_header  = request.headers.get('Authorization')

        if not auth_header:
            return Response({
                        'title' : 'failed',
                        'message': 'Authorization header is missing',
                    },
                status=status.HTTP_400_BAD_REQUEST
            )
        
        token = auth_header .split(' ')[1]
        findTokenUser = get_object_or_404(Token, key=token)
        if findTokenUser:
            findUser = get_object_or_404(User, id=findTokenUser.user_id)
            data_obj = {
                'username' : findUser.username,
                'email' : findUser.email,
                'first_name' : findUser.first_name,
                'last_name' : findUser.last_name,
            }

            return Response({
                'title' : 'succeed',
                'message': 'successfully get user profile',
                'data' : {
                        'info_user' : data_obj,
                        'token' : token,
                    },
                }, status=status.HTTP_200_OK)
        return Response({
                'title' : 'failed',
                'message': findTokenUser.error,
                }, status=status.HTTP_401_UNAUTHORIZED)
        
class UserViewSetJWT(viewsets.ViewSet):
    permission_classes = []

    @action(detail=False, methods=['POST']) # DECORATOR
    def sign_in(self, request, *args, **kwargs):
        username = request.data['username']
        password = request.data['password']
        userAuth = authenticate(username=username, password=password)
        
        if userAuth:
            findUsers = get_object_or_404(User, username=username)
            data_obj = {
                'username' : findUsers.username,
                'email' : findUsers.email,
                'first_name' : findUsers.first_name,
                'last_name' : findUsers.last_name,
            }
            token = ''

            return Response({
                'title' : 'succeed',
                'message': 'successfully logged in',
                'data' : {
                        'info_user' : data_obj,
                        'token' : token
                    },
                }, status=status.HTTP_200_OK)
        
        return Response({
                'title' : 'failed',
                'message': 'Make sure the username and password are correct and also we cannot find an account with that data.',
                'response' : userAuth,
            }, status=status.HTTP_400_BAD_REQUEST)