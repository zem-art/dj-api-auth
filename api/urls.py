from django.urls import path, include
from .views import UserViewSet, GroupViewSet, UserRegisterView, UserViewSets, UserViewSetJWT
from rest_framework.routers import DefaultRouter
from rest_framework.authtoken.views import obtain_auth_token
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

app_name = 'api'

# Membuat router untuk ViewSet
router = DefaultRouter()
router.register(r'users', UserViewSet, basename='user')
router.register(r'groups', GroupViewSet, basename='group')
router.register(r'auth', UserViewSets, basename='auth_view_set')
router.register(r'auth/jwt', UserViewSetJWT, basename='auth_view_set_jwt')

urlpatterns = [
    path('', include(router.urls)),

    # path('token/', obtain_auth_token, name='api_token_auth'),
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('authentications/register/api_view', UserRegisterView.as_view(), name='auth_signup_api_view'),
    path('auth/', include('rest_framework.urls', namespace='rest_framework')),
]