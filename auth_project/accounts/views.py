from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.conf import settings
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_str

from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated

from .models import User, UserProfile, LoginHistory
from .forms import (
    UserRegistrationForm,
    UserLoginForm,
    PasswordResetForm,
    PasswordResetConfirmForm,
    ProfileUpdateForm
)
from .utils import validate_password_strength
from .decorators import role_required, check_session_timeout
import uuid
import logging

logger = logging.getLogger(__name__)


def is_admin_user(user):
    """Check if user has admin role."""
    return user.is_authenticated and user.role == 'admin'


@require_http_methods(["GET", "POST"])
def register_view(request):
    """Handle user registration."""
    if request.user.is_authenticated:
        return redirect('dashboard')
    
    if request.method == 'POST':
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            try:
                # Validate password strength
                password = form.cleaned_data['password1']
                password_strength = validate_password_strength(password)
                
                if not password_strength['is_valid']:
                    messages.error(request, password_strength['message'])
                    return render(request, 'accounts/register.html', {'form': form})
                
                # Create user
                user = form.save(commit=False)
                user.is_active = True  # User can login but email not verified
                user.save()
                
                # Create user profile
                UserProfile.objects.create(user=user)
                
                # Send verification email
                user.send_verification_email(request)
                
                messages.success(
                    request,
                    'Registration successful! Please check your email to verify your account.'
                )
                return redirect('login')
                
            except Exception as e:
                logger.error(f"Registration error: {e}")
                messages.error(request, 'An error occurred during registration. Please try again.')
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = UserRegistrationForm()
    
    return render(request, 'accounts/register.html', {'form': form})


@require_http_methods(["GET", "POST"])
def login_view(request):
    """Handle user login."""
    if request.user.is_authenticated:
        return redirect('dashboard')
    
    if request.method == 'POST':
        # Manual form handling for simple form
        email = request.POST.get('username')
        password = request.POST.get('password')
        
        if not email or not password:
            messages.error(request, 'Please enter both email and password.')
            return render(request, 'accounts/login.html')
        
        user = authenticate(request, email=email, password=password)
        
        if user is not None:
            # Check if email is verified
            if not user.is_email_verified:
                messages.warning(
                    request,
                    'Please verify your email before logging in. '
                    'Check your email for the verification link.'
                )
                return render(request, 'accounts/login.html')
            
            # Check if account is active
            if not user.is_active:
                messages.error(request, 'Your account is inactive.')
                return render(request, 'accounts/login.html')
            
            # Log the user in
            login(request, user)
            
            # Record login history
            LoginHistory.objects.create(
                user=user,
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                session_key=request.session.session_key or 'unknown'
            )
            
            messages.success(request, f'Welcome back, {user.first_name or user.email}!')
            
            # Redirect based on role
            if user.role == 'admin':
                return redirect('admin-dashboard')
            else:
                return redirect('dashboard')
        else:
            messages.error(request, 'Invalid email or password.')
    else:
        # Check for session expired parameter
        if request.GET.get('session_expired'):
            messages.warning(request, 'Your session has expired due to inactivity.')
    
    return render(request, 'accounts/login.html')


@login_required
@login_required
def logout_view(request):
    """Handle user logout."""
    logout(request)
    messages.info(request, 'You have been logged out successfully.')
    return redirect('home')


@require_http_methods(["GET", "POST"])
def password_reset_view(request):
    """Handle password reset request."""
    if request.user.is_authenticated:
        return redirect('dashboard')
    
    if request.method == 'POST':
        form = PasswordResetForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            try:
                user = User.objects.get(email=email)
                user.send_password_reset_email(request)
                messages.success(
                    request,
                    'Password reset link has been sent to your email.'
                )
                return redirect('login')
            except User.DoesNotExist:
                messages.error(request, 'No user found with this email address.')
    else:
        form = PasswordResetForm()
    
    return render(request, 'accounts/password_reset.html', {'form': form})


@require_http_methods(["GET", "POST"])
def password_reset_confirm_view(request, token):
    """Handle password reset confirmation."""
    if request.user.is_authenticated:
        return redirect('dashboard')
    
    try:
        user = User.objects.get(password_reset_token=token)
        
        # Check if token is expired
        if (user.password_reset_token_expires and 
            user.password_reset_token_expires < timezone.now()):
            messages.error(request, 'Password reset link has expired.')
            return redirect('password-reset')
        
        if request.method == 'POST':
            form = PasswordResetConfirmForm(request.POST)
            if form.is_valid():
                # Validate password strength
                password = form.cleaned_data['new_password1']
                password_strength = validate_password_strength(password)
                
                if not password_strength['is_valid']:
                    messages.error(request, password_strength['message'])
                    return render(request, 'accounts/password_reset_confirm.html', {
                        'form': form,
                        'token': token
                    })
                
                # Set new password
                user.set_password(password)
                user.password_reset_token = None
                user.password_reset_token_expires = None
                user.save()
                
                messages.success(request, 'Your password has been reset successfully.')
                return redirect('login')
        else:
            form = PasswordResetConfirmForm()
        
        return render(request, 'accounts/password_reset_confirm.html', {
            'form': form,
            'token': token
        })
        
    except (User.DoesNotExist, ValidationError):
        messages.error(request, 'Invalid password reset link.')
        return redirect('password-reset')


def verify_email_view(request, token):
    """Handle email verification."""
    try:
        user = User.objects.get(email_verification_token=token)
        
        # Check if token is expired (24 hours)
        if (user.email_verification_sent_at and 
            user.email_verification_sent_at < timezone.now() - timezone.timedelta(hours=24)):
            messages.error(request, 'Verification link has expired.')
            return redirect('resend-verification')
        
        user.is_email_verified = True
        user.email_verification_token = uuid.uuid4()  # Generate new token
        user.save()
        
        messages.success(request, 'Your email has been verified successfully. You can now log in.')
        return redirect('login')
        
    except User.DoesNotExist:
        messages.error(request, 'Invalid verification link.')
        return redirect('register')


@require_http_methods(["GET", "POST"])
def resend_verification_view(request):
    """Resend verification email."""
    if request.user.is_authenticated:
        return redirect('dashboard')
    
    if request.method == 'POST':
        email = request.POST.get('email')
        try:
            user = User.objects.get(email=email)
            
            if user.is_email_verified:
                messages.info(request, 'Your email is already verified.')
                return redirect('login')
            
            # Check if we should resend (prevent spam)
            if (user.email_verification_sent_at and 
                user.email_verification_sent_at > timezone.now() - timezone.timedelta(minutes=5)):
                messages.info(request, 'Please wait 5 minutes before requesting another verification email.')
                return render(request, 'accounts/resend_verification.html')
            
            user.send_verification_email(request)
            messages.success(request, 'Verification email has been resent.')
            return redirect('login')
            
        except User.DoesNotExist:
            messages.error(request, 'No user found with this email address.')
    
    return render(request, 'accounts/resend_verification.html')


@login_required
@check_session_timeout
def dashboard_view(request):
    """User dashboard."""
    user = request.user
    login_history = LoginHistory.objects.filter(user=user).order_by('-login_time')[:10]
    
    context = {
        'user': user,
        'login_history': login_history,
        'session_timeout': settings.SESSION_COOKIE_AGE,
    }
    
    return render(request, 'accounts/dashboard.html', context)


@login_required
@role_required('admin')
@check_session_timeout
def admin_dashboard_view(request):
    """Admin dashboard."""
    users = User.objects.all().order_by('-date_joined')
    
    context = {
        'users': users,
        'total_users': users.count(),
        'active_users': users.filter(is_active=True).count(),
        'verified_users': users.filter(is_email_verified=True).count(),
    }
    
    return render(request, 'accounts/admin_dashboard.html', context)


@login_required
@check_session_timeout
def profile_view(request):
    """User profile view."""
    if request.method == 'POST':
        form = ProfileUpdateForm(request.POST, request.FILES, instance=request.user.profile)
        if form.is_valid():
            form.save()
            messages.success(request, 'Profile updated successfully.')
            return redirect('profile')
    else:
        form = ProfileUpdateForm(instance=request.user.profile)
    
    return render(request, 'accounts/profile.html', {'form': form})


@api_view(['POST'])
@permission_classes([AllowAny])
def api_login(request):
    """API endpoint for login (returns JWT tokens)."""
    email = request.data.get('email')
    password = request.data.get('password')
    
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
    
    return Response({
        'refresh': str(refresh),
        'access': str(refresh.access_token),
        'user': {
            'id': user.id,
            'email': user.email,
            'role': user.role,
            'first_name': user.first_name,
            'last_name': user.last_name,
        }
    })


@login_required
@check_session_timeout
@require_http_methods(["GET"])
def session_status_view(request):
    """Check session status for auto-timeout."""
    # Don't require login for this endpoint
    if request.user.is_authenticated:
        # Update last activity
        request.user.last_activity = timezone.now()
        request.user.save(update_fields=['last_activity'])
        
        # Calculate remaining time
        from django.conf import settings
        session_age = settings.SESSION_COOKIE_AGE
        session_last_activity = request.session.get('last_activity')
        
        if session_last_activity:
            elapsed = timezone.now().timestamp() - session_last_activity
            remaining = max(0, session_age - elapsed)
        else:
            remaining = session_age
        
        return JsonResponse({
            'authenticated': True,
            'remaining_time': remaining,
            'timeout': session_age,
            'user': {
                'email': request.user.email,
                'role': request.user.role,
            }
        })
    
    return JsonResponse({
        'authenticated': False,
        'remaining_time': 0,
        'timeout': 900
    })
@csrf_exempt
@login_required
def extend_session_view(request):
    """Extend session if user is active."""
    if request.method == 'POST':
        # Reset session expiry
        request.session.modified = True
        request.session.set_expiry(settings.SESSION_COOKIE_AGE)
        
        # Update last activity
        request.user.last_activity = timezone.now()
        request.user.save(update_fields=['last_activity'])
        
        return JsonResponse({'success': True})
    
    return JsonResponse({'success': False}, status=400)


def get_client_ip(request):
    """Get client IP address."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip