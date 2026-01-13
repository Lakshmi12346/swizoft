from rest_framework import viewsets, permissions, status, generics
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from django.contrib.auth import get_user_model, authenticate
from django.utils import timezone
from django.shortcuts import get_object_or_404
from django.core.exceptions import ValidationError
import uuid

from .serializers import (
    UserSerializer, UserCreateSerializer, PasswordChangeSerializer,
    PasswordResetSerializer, PasswordResetConfirmSerializer
)
from accounts.models import LoginHistory

User = get_user_model()


class UserViewSet(viewsets.ModelViewSet):
    """API endpoint for users."""
    queryset = User.objects.all().order_by('-date_joined')
    permission_classes = [IsAuthenticated]
    
    def get_serializer_class(self):
        if self.action == 'create':
            return UserCreateSerializer
        return UserSerializer
    
    def get_permissions(self):
        """Set permissions based on action."""
        if self.action in ['create', 'list']:
            permission_classes = [AllowAny] if self.action == 'create' else [permissions.IsAdminUser]
        elif self.action in ['update', 'partial_update', 'destroy']:
            permission_classes = [permissions.IsAdminUser]
        else:
            permission_classes = [IsAuthenticated]
        return [permission() for permission in permission_classes]
    
    def get_queryset(self):
        """Filter queryset based on user role."""
        if self.request.user.role == 'admin' or self.request.user.is_superuser:
            return User.objects.all()
        return User.objects.filter(id=self.request.user.id)
    
    @action(detail=False, methods=['get'])
    def me(self, request):
        """Get current user profile."""
        serializer = self.get_serializer(request.user)
        return Response(serializer.data)
    
    @action(detail=False, methods=['post'], permission_classes=[IsAuthenticated])
    def change_password(self, request):
        """Change user password."""
        serializer = PasswordChangeSerializer(data=request.data, context={'request': request})
        
        if serializer.is_valid():
            user = request.user
            user.set_password(serializer.validated_data['new_password'])
            user.save()
            
            # Update last activity
            user.last_activity = timezone.now()
            user.save(update_fields=['last_activity'])
            
            return Response({'message': 'Password updated successfully.'})
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=False, methods=['get'], permission_classes=[permissions.IsAdminUser])
    def stats(self, request):
        """Get user statistics (admin only)."""
        total_users = User.objects.count()
        active_users = User.objects.filter(is_active=True).count()
        verified_users = User.objects.filter(is_email_verified=True).count()
        admin_users = User.objects.filter(role='admin').count()
        
        return Response({
            'total_users': total_users,
            'active_users': active_users,
            'verified_users': verified_users,
            'admin_users': admin_users,
        })


@api_view(['POST'])
@permission_classes([AllowAny])
def api_login(request):
    """API endpoint for login (returns JWT tokens)."""
    email = request.data.get('email')
    password = request.data.get('password')
    
    if not email or not password:
        return Response(
            {'error': 'Email and password are required'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    user = authenticate(email=email, password=password)
    
    if user is None:
        return Response(
            {'error': 'Invalid credentials'},
            status=status.HTTP_401_UNAUTHORIZED
        )
    
    if not user.is_email_verified:
        return Response(
            {'error': 'Email not verified'},
            status=status.HTTP_403_FORBIDDEN
        )
    
    if not user.is_active:
        return Response(
            {'error': 'Account is inactive'},
            status=status.HTTP_403_FORBIDDEN
        )
    
    # Generate JWT tokens
    from rest_framework_simplejwt.tokens import RefreshToken
    refresh = RefreshToken.for_user(user)
    
    # Record login history
    ip_address = get_client_ip(request)
    LoginHistory.objects.create(
        user=user,
        ip_address=ip_address,
        user_agent=request.META.get('HTTP_USER_AGENT', ''),
        session_key=f"api_{user.id}_{timezone.now().timestamp()}"
    )
    
    # Update last activity
    user.last_activity = timezone.now()
    user.save(update_fields=['last_activity'])
    
    return Response({
        'refresh': str(refresh),
        'access': str(refresh.access_token),
        'user': {
            'id': user.id,
            'email': user.email,
            'role': user.role,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'is_email_verified': user.is_email_verified,
        }
    })


@api_view(['POST'])
@permission_classes([AllowAny])
def password_reset_request(request):
    """Request password reset."""
    serializer = PasswordResetSerializer(data=request.data)
    
    if serializer.is_valid():
        email = serializer.validated_data['email']
        try:
            user = User.objects.get(email=email)
            user.send_password_reset_email(request._request)  # Pass Django request
            
            return Response({
                'message': 'Password reset link has been sent to your email.'
            })
            
        except User.DoesNotExist:
            # Don't reveal that user doesn't exist for security
            return Response({
                'message': 'If an account exists with this email, you will receive a password reset link.'
            })
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([AllowAny])
def password_reset_confirm(request):
    """Confirm password reset."""
    serializer = PasswordResetConfirmSerializer(data=request.data)
    
    if serializer.is_valid():
        token = serializer.validated_data['token']
        new_password = serializer.validated_data['new_password']
        
        try:
            user = User.objects.get(password_reset_token=token)
            
            # Check if token is expired
            if (user.password_reset_token_expires and 
                user.password_reset_token_expires < timezone.now()):
                return Response(
                    {'error': 'Password reset link has expired.'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Set new password
            user.set_password(new_password)
            user.password_reset_token = None
            user.password_reset_token_expires = None
            user.save()
            
            return Response({'message': 'Password has been reset successfully.'})
            
        except User.DoesNotExist:
            return Response(
                {'error': 'Invalid password reset link.'},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@permission_classes([AllowAny])
def verify_email(request, token):
    """Verify email address."""
    try:
        user = User.objects.get(email_verification_token=token)
        
        # Check if token is expired (24 hours)
        if (user.email_verification_sent_at and 
            user.email_verification_sent_at < timezone.now() - timezone.timedelta(hours=24)):
            return Response(
                {'error': 'Verification link has expired.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        user.is_email_verified = True
        user.email_verification_token = uuid.uuid4()  # Generate new token
        user.save()
        
        return Response({'message': 'Your email has been verified successfully.'})
        
    except User.DoesNotExist:
        return Response(
            {'error': 'Invalid verification link.'},
            status=status.HTTP_400_BAD_REQUEST
        )


@api_view(['POST'])
@permission_classes([AllowAny])
def resend_verification(request):
    """Resend verification email."""
    email = request.data.get('email')
    
    if not email:
        return Response(
            {'error': 'Email is required'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        user = User.objects.get(email=email)
        
        if user.is_email_verified:
            return Response(
                {'message': 'Your email is already verified.'}
            )
        
        # Check if we should resend (prevent spam)
        if (user.email_verification_sent_at and 
            user.email_verification_sent_at > timezone.now() - timezone.timedelta(minutes=5)):
            return Response(
                {'error': 'Please wait 5 minutes before requesting another verification email.'},
                status=status.HTTP_429_TOO_MANY_REQUESTS
            )
        
        user.send_verification_email(request._request)  # Pass Django request
        
        return Response({'message': 'Verification email has been resent.'})
        
    except User.DoesNotExist:
        return Response(
            {'error': 'No user found with this email address.'},
            status=status.HTTP_404_NOT_FOUND
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def session_status(request):
    """Check session status for auto-timeout."""
    user = request.user
    
    # Update last activity
    user.last_activity = timezone.now()
    user.save(update_fields=['last_activity'])
    
    # Get session info
    from django.conf import settings
    session_age = settings.SESSION_COOKIE_AGE
    last_activity = request.session.get('last_activity')
    
    if last_activity:
        elapsed = timezone.now().timestamp() - last_activity
        remaining = max(0, session_age - elapsed)
    else:
        remaining = session_age
    
    return Response({
        'authenticated': True,
        'remaining_time': remaining,
        'timeout': session_age,
        'user': {
            'email': user.email,
            'role': user.role,
            'first_name': user.first_name,
            'last_name': user.last_name,
        }
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def extend_session(request):
    """Extend session if user is active."""
    # Reset session expiry
    request.session.modified = True
    
    # Update last activity
    user = request.user
    user.last_activity = timezone.now()
    user.save(update_fields=['last_activity'])
    
    return Response({
        'success': True,
        'message': 'Session extended successfully.'
    })


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def login_history(request):
    """Get user login history."""
    user = request.user
    history = LoginHistory.objects.filter(user=user).order_by('-login_time')[:20]
    
    data = []
    for entry in history:
        data.append({
            'ip_address': entry.ip_address,
            'user_agent': entry.user_agent[:100],  # Truncate long user agents
            'login_time': entry.login_time,
            'logout_time': entry.logout_time,
            'duration': str(entry.logout_time - entry.login_time) if entry.logout_time else None
        })
    
    return Response(data)


def get_client_ip(request):
    """Get client IP address."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip