from django.urls import path, include
from .views import UserViewSet, GroupViewSet
from rest_framework.routers import DefaultRouter

app_name = 'api'

# Membuat router untuk ViewSet
router = DefaultRouter()
router.register(r'users', UserViewSet, basename='user')
router.register(r'groups', GroupViewSet, basename='group')

urlpatterns = [
    path('', include(router.urls)),
]