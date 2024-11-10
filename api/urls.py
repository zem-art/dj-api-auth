from django.urls import path, include
from .views import UserViewSet, GroupViewSet, UserRegisterView, UserViewSets, UserViewSetJWT, TodoViewSets
from rest_framework.routers import DefaultRouter
from rest_framework.authtoken.views import obtain_auth_token
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

app_name = 'api'

# Membuat router untuk ViewSet
router = DefaultRouter()
router.register(r'users', UserViewSet, basename='user')
router.register(r'groups', GroupViewSet, basename='group')
router.register(r'auth/view', UserViewSets, basename='auth_view_set')
router.register(r'auth', UserViewSetJWT, basename='auth_jwt')
router.register(r'todos', TodoViewSets, basename='todos')

urlpatterns = [
    path('', include(router.urls)),

    # path('token/', obtain_auth_token, name='api_token_auth'),
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('authentications/register/api_view', UserRegisterView.as_view(), name='auth_signup_api_view'),
    path('auth/', include('rest_framework.urls', namespace='rest_framework')),

    # auth view jwt
    path('auth/jwt/sign_in/', UserViewSetJWT.as_view({'post' : 'sign_in'}), name='sign_in'),
    path('auth/jwt/profile/', UserViewSetJWT.as_view({'get' : 'profile'}), name='profile'),
    path('todos/create/', TodoViewSets.as_view({'post' : 'create'}), name='todos_create'),
    path('todos/list/', TodoViewSets.as_view({'get' : 'list'}), name='todos_list'),
]