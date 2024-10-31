from django.urls import path, re_path
from .views import UserViewSet, GroupViewSet

urlpatterns = [
    path('user/', UserViewSet()),
]