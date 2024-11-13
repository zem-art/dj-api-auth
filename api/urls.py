from django.urls import path, include, re_path
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
    path('todo/all/list/', TodoViewSets.as_view({'get' : 'list'}), name='todos_list'),
    path('todo/create/', TodoViewSets.as_view({'post' : 'create'}), name='todo_create'),
    re_path(r'^todo/(?P<uid>[a-zA-Z0-9]+)/update/$', TodoViewSets.as_view({'put' : 'update'}), name='todo_update'),
    re_path(r'^todo/(?P<uid>[a-zA-Z0-9]+)/detail/$', TodoViewSets.as_view({'get' : 'retrieve'}), name='todo_retrieve'),
    re_path(r'^todo/(?P<uid>[a-zA-Z0-9]+)/temporary/delete/$', TodoViewSets.as_view({'delete' : 'temporary_delete'}), name='todo_temporary_delete'),
    re_path(r'^todo/(?P<uid>[a-zA-Z0-9]+)/recovery/delete/$', TodoViewSets.as_view({'put' : 'recovery_delete'}), name='todo_recovery_delete'),
]