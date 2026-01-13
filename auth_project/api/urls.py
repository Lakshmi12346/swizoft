from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView
from . import views

router = DefaultRouter()
router.register(r'users', views.UserViewSet, basename='user')

urlpatterns = [
    path('', include(router.urls)),
    
    # Authentication endpoints
    path('auth/login/', views.api_login, name='api-login'),
    path('auth/token/refresh/', TokenRefreshView.as_view(), name='token-refresh'),
    path('auth/password/reset/', views.password_reset_request, name='api-password-reset'),
    path('auth/password/reset/confirm/', views.password_reset_confirm, name='api-password-reset-confirm'),
    path('auth/verify-email/<uuid:token>/', views.verify_email, name='api-verify-email'),
    path('auth/resend-verification/', views.resend_verification, name='api-resend-verification'),
    
    # Session endpoints
    path('session/status/', views.session_status, name='api-session-status'),
    path('session/extend/', views.extend_session, name='api-extend-session'),
]