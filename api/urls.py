from django.urls import path, include
from .views import UserViewSet, GroupViewSet, UserRegisterView, UserViewSets
from rest_framework.routers import DefaultRouter
from rest_framework.authtoken.views import obtain_auth_token

app_name = 'api'

# Membuat router untuk ViewSet
router = DefaultRouter()
router.register(r'users', UserViewSet, basename='user')
router.register(r'groups', GroupViewSet, basename='group')
router.register(r'authentications', UserViewSets, basename='authentication')

urlpatterns = [
    path('', include(router.urls)),
    path('token/', obtain_auth_token, name='api_token_auth'),
    path('authentications/register/api_view', UserRegisterView.as_view(), name='auth_signup_api_view'),
    path('auth/', include('rest_framework.urls', namespace='rest_framework')),
]