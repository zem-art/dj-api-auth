from django.urls import path, include
from .views import UserViewSet, GroupViewSet, UserRegisterView
from rest_framework.routers import DefaultRouter
from rest_framework.authtoken.views import obtain_auth_token

app_name = 'api'

# Membuat router untuk ViewSet
router = DefaultRouter()
router.register(r'users', UserViewSet, basename='user')
router.register(r'groups', GroupViewSet, basename='group')

urlpatterns = [
    path('', include(router.urls)),
    path('register/', UserRegisterView.as_view(), name='user_registration'),
    path('auth/', include('rest_framework.urls', namespace='rest_framework')),
    path('token/', obtain_auth_token, name='api_token_auth'),
]