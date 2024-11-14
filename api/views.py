import re
import time
from datetime import datetime
from django.http import Http404
from django.conf import settings
from django.shortcuts import render, get_object_or_404
from django.contrib.auth.models import Group, User
from django.contrib.auth import authenticate
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework import permissions, viewsets, status
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from rest_framework.views import APIView
from rest_framework.decorators import action
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework_simplejwt.views import TokenObtainPairView
from .serializers import GroupSerializer, UserSerializer, UserSerializateRegister, TodoSerializate, ImageSerializate
from .models import TodoModel
from utils import date, pagination, random, response, timestamp, firebase_upload_image

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
    
    """
        ## Refrensi : class
        - Django REST Framework Decorator
        - Django REST Framework - Custom Actions
    """

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
        
        token = auth_header.split(' ')[1]
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

    """
        ## Refrensi : JWT token
        - JWT.io
        - Django REST Framework Simple JWT - Token Types
        - Django REST Framework Authentication
        - Django REST Framework - Routers
        - Django REST Framework - Custom Actions
        - Django REST Framework - ViewSets
    """

    def sign_in(self, request, *args, **kwargs):
        username = request.data['username']
        password = request.data['password']
        userAuth = authenticate(username=username, password=password)

        if userAuth is not None:
            findUsers = get_object_or_404(User, username=username)
            res_data_obj = {
                'username' : findUsers.username,
                'email' : findUsers.email,
                'first_name' : findUsers.first_name,
                'last_name' : findUsers.last_name,
            }

            serializer = TokenObtainPairSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            token_data = serializer.validated_data # return : access token & refresh token

            return Response({
                'title' : 'succeed',
                'message': 'successfully logged in',
                'data' : {
                        'info_user' : res_data_obj,
                        'token' : token_data['access']
                    },
                }, status=status.HTTP_200_OK)
        else:
            return Response({
                    'title' : 'failed',
                    'message': 'Make sure the username and password are correct and also we cannot find an account with that data.',
                    'response' : userAuth,
                }, status=status.HTTP_401_UNAUTHORIZED)


    @action(detail=False, methods=['GET'], permission_classes=[IsAuthenticated], url_path='profile')
    def profile(self, request, *args, **kwargs):

        auth_header  = request.headers.get('Authorization')

        if not auth_header:
            return Response({
                        'title' : 'failed',
                        'message': 'Authorization header is missing',
                    },
                status=status.HTTP_400_BAD_REQUEST
            )

        # Mendekode dan memverifikasi token
        try:
            token = auth_header.split(' ')[1]
            access_token = AccessToken(token)

            # Mendapatkan user dari token
            user = access_token['user_id']
            findUser = get_object_or_404(User, id=user)
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
        except Exception as e:
            return Response({
                    'title' : 'failed',
                    'message': 'Token is invalid or expired'
                }, status=status.HTTP_401_UNAUTHORIZED)
            
            
class TodoViewSets(viewsets.ViewSet):

    permission_classes = [IsAuthenticated]

    def create(self, request, *args, **kwargs):
        serializate = TodoSerializate(data=request.data)

        if serializate.is_valid():
            serializate.save()
            data = {
                'uid' : serializate.data['uid'],
                'title' : serializate.data['title'],
                'description' : serializate.data['description'],
                'completed' : serializate.data['completed'],
                'created_at': date.convert_datetime_format(serializate.data['created_at']),
                'updated_at': date.convert_datetime_format(serializate.data['updated_at']),
            }
            return response.create_custom_response(
                title='succeed',
                message='successfully create todo',
                status_code=status.HTTP_201_CREATED,
                error=None,
                data=data
            )
        else:
            return response.create_custom_response(
                title='failed',
                message='failed create todo',
                status_code=status.HTTP_400_BAD_REQUEST,
                error=serializate.error_messages,
                data=None
            )
   
    def list(self, request, *args, **kwargs):
        """
        NOTE :
        - many=True on serializer is used to convert queryset into JSON format, so that all todo data can be displayed in the response.
        """
        queryset = TodoModel.objects.filter(deleted_flag=False, deleted_at=None).order_by('-created_at')
        # Inisialisasi pagination
        paginator = pagination.CustomPageNumberPagination()

        result_page = paginator.paginate_queryset(queryset, request)
        serializer_class = TodoSerializate(result_page, many=True)

        array_push = []
        if len(serializer_class.data) > 0:
            for item in serializer_class.data:

                array_push.append({
                    'uid' : item.get("uid"),
                    'title': item.get("title"),
                    'description': item.get("description"),
                    'completed': item.get("completed"),
                    'deleted_flag' : item.get("deleted_flag"),
                    'created_at': date.convert_datetime_format(item.get('created_at')),
                    'updated_at': date.convert_datetime_format(item.get('updated_at')),
                })

        data = {
            'list_todos' : array_push
        }
        return response.create_custom_response(
            title='succeed',
            message='successfully list all todos',
            status_code=status.HTTP_200_OK,
            error=None,
            data=data
        )
    
    def retrieve(self, request, *args, **kwargs):
        params_uid = self.kwargs['uid']

        try:
            todo_instance = get_object_or_404(TodoModel, uid=params_uid, deleted_flag=False, deleted_at=None)
            serializer = TodoSerializate(todo_instance)
            data = {
                'uid' : serializer.data['uid'],
                'title' : serializer.data['title'],
                'description' : serializer.data['description'],
                'completed' : serializer.data['completed'],
                'created_at': date.convert_datetime_format(serializer.data['created_at']),
                'updated_at': date.convert_datetime_format(serializer.data['updated_at']),
            }
            return response.create_custom_response(
                title='succeed',
                message='successfully get todos',
                status_code=status.HTTP_200_OK,
                error=None,
                data=data
            )
        except Http404:
            return response.create_custom_response(
                title='failed',
                message=f"Data with UUID {params_uid} not found.",
                error="Not Found",
                status_code=status.HTTP_404_NOT_FOUND,
                data= None
            )

    def update(self, request, *args, **kwargs):
        params_uid = self.kwargs['uid']

        try:
            todo_instance = get_object_or_404(TodoModel, uid=params_uid, deleted_flag=False, deleted_at=None)
            serializate = TodoSerializate(todo_instance, data=request.data, partial=True)  # partial=True untuk update parsial

            if serializate.is_valid():
                serializate.save()
                data = {
                    'uid' : serializate.data['uid'],
                    'title' : serializate.data['title'],
                    'description' : serializate.data['description'],
                    'completed' : serializate.data['completed'],
                    'created_at': date.convert_datetime_format(serializate.data['created_at']),
                    'updated_at': date.convert_datetime_format(serializate.data['updated_at']),
                }
                return response.create_custom_response(
                    title='succeed',
                    message='successfully update todos',
                    status_code=status.HTTP_200_OK,
                    error=None,
                    data=data
                )
        except Exception as err:
            return response.create_custom_response(
                title='failed',
                message='failed update todo',
                status_code=status.HTTP_400_BAD_REQUEST,
                error=str(err),
                data=None
            )
          
    def list_delete_todos(self, request, *args, **kwargs):
        queryset = TodoModel.objects.filter(deleted_flag=True).order_by('-created_at')
        # Inisialisasi pagination
        paginator = pagination.CustomPageNumberPagination()

        result_page = paginator.paginate_queryset(queryset, request)
        serializer_class = TodoSerializate(result_page, many=True)

        array_push = []
        if len(serializer_class.data) > 0:
            for item in serializer_class.data:

                array_push.append({
                    'uid' : item.get("uid"),
                    'title': item.get("title"),
                    'description': item.get("description"),
                    'completed': item.get("completed"),
                    'deleted_flag' : item.get("deleted_flag"),
                    'created_at': date.convert_datetime_format(item.get('created_at')),
                    'updated_at': date.convert_datetime_format(item.get('updated_at')),
                    'deleted_at': date.convert_datetime_format(item.get('deleted_at')),
                })

        data = {
            'list_todos' : array_push
        }
        return response.create_custom_response(
            title='succeed',
            message='successfully list all todos delete',
            status_code=status.HTTP_200_OK,
            error=None,
            data=data
        )
    
    def temporary_delete(self, request, *args, **kwargs):
        params_uid = self.kwargs['uid']

        try:
            todo_instance = get_object_or_404(TodoModel, uid=params_uid, deleted_flag=False, deleted_at=None)
            request.data['deleted_flag'] = True
            request.data['deleted_at'] = datetime.now()

            serializate = TodoSerializate(todo_instance, data=request.data, partial=True)
            if serializate.is_valid():
                serializate.save()
                return response.create_custom_response(
                    title='succeed',
                    message= f'successfully delete temporary todos uid : {params_uid}',
                    status_code=status.HTTP_200_OK,
                    error=None,
                    data=None,
                )
        except Exception as err:
          return response.create_custom_response(
                title='failed',
                message='failed delete todo',
                status_code=status.HTTP_400_BAD_REQUEST,
                error=str(err),
                data=None,
            )
          
    def recovery_delete(self, request, *args, **kwargs):
        params_uid = self.kwargs['uid']

        try:
            todo_instance = get_object_or_404(TodoModel, uid=params_uid, deleted_flag=True)
            request.data['deleted_flag'] = False
            request.data['deleted_at'] = None

            serializate = TodoSerializate(todo_instance, data=request.data, partial=True)
            if serializate.is_valid():
                serializate.save()
                return response.create_custom_response(
                    title='succeed',
                    message= f'successfully recovery delete todos uid : {params_uid}',
                    status_code=status.HTTP_200_OK,
                    error=None,
                    data=None,
                )
        except Exception as err:
          return response.create_custom_response(
                title='failed',
                message='failed recovery delete todo',
                status_code=status.HTTP_400_BAD_REQUEST,
                error=str(err),
                data=None,
            )
    
    def delete(self, request, *args, **kwargs):
        params_uid = self.kwargs['uid']

        try:
            todo_instance = get_object_or_404(TodoModel, uid=params_uid, deleted_flag=True)
            todo_instance.delete()
            return response.create_custom_response(
                    title='succeed',
                    message= f'successfully delete todos uid : {params_uid}',
                    status_code=status.HTTP_200_OK,
                    error=None,
                    data=None,
                )
        except Exception as err:
          return response.create_custom_response(
                title='failed',
                message='failed delete todo',
                status_code=status.HTTP_400_BAD_REQUEST,
                error=str(err),
                data=None,
            )


class ImageUploadTodo(viewsets.ViewSet):
    permission_classes = []

    def create(self, request, *args, **kwargs):

        image_file = request.FILES.get('image')
        uid = request.data['uid_todo']

        try:
            if not image_file:
                return response.create_custom_response(
                    title='failed',
                    message='No image file provided.',
                    status_code=status.HTTP_400_BAD_REQUEST,
                    error='Not Found',
                    data=None,
                )

            if image_file.size > settings.MAX_UPLOAD_SIZE_KB * 1024: # covert to KB
                return response.create_custom_response(
                    title='failed',
                    message=f"Image size should not exceed {settings.MAX_UPLOAD_SIZE_KB} KB.", # in MB = settings.MAX_UPLOAD_SIZE_MB / (1024 * 1024)
                    status_code=status.HTTP_400_BAD_REQUEST,
                    error='Bad Request',
                    data=None,
                )

            # Menambahkan timestamp pada nama file yang baru akan diupload
            timestamp = int(time.time())
            file_name, file_extension = image_file.name.rsplit('.', 1)

            # Hapus karakter khusus dari file_name baru
            clean_file_name = re.sub(r'[^A-Za-z0-9_]', '', file_name.upper())
            new_image_name = f"{clean_file_name}-{timestamp}.{file_extension}"

            firebase_uploader = firebase_upload_image.FirebaseImageUploader()
            image_url = firebase_uploader.upload_image(image_file, f'images_api_todos/{new_image_name}')

            todo_instance = get_object_or_404(TodoModel, uid=uid)
            serializer_todo = TodoSerializate(todo_instance)
            req_data = {
                'uid_todo' : serializer_todo.data['uid'],
                'link_image_todo' : image_url,
                'todo_id' : serializer_todo.data['id'],
            }
            serializate = ImageSerializate(data=req_data)

            if serializate.is_valid():
                serializate.save()
                resp = serializate.data
                return response.create_custom_response(
                    title='succeed',
                    message='successfully upload image',
                    status_code=status.HTTP_200_OK,
                    error=None,
                    data=resp
                )
            else:
                return response.create_custom_response(
                    title='failed',
                    message='failed create todo',
                    status_code=status.HTTP_400_BAD_REQUEST,
                    error=serializate.error_messages,
                    data=None
                )
        except Exception as err:
          return response.create_custom_response(
                title='failed',
                message='failed upload image todo',
                status_code=status.HTTP_400_BAD_REQUEST,
                error=str(err),
                data=None
            )