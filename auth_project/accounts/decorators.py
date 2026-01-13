from django.contrib.auth import logout
from django.shortcuts import redirect
from django.urls import reverse
from django.http import JsonResponse
from functools import wraps
from django.utils import timezone
import time


def role_required(required_role):
    """Decorator to check user role."""
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return redirect('login')
            
            if request.user.role != required_role and not request.user.is_superuser:
                from django.contrib import messages
                messages.error(request, 'You do not have permission to access this page.')
                return redirect('dashboard')
            
            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator


def check_session_timeout(view_func):
    """Decorator to check session timeout before view execution."""
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('login')
        
        # Check session timeout
        last_activity = request.session.get('last_activity')
        current_time = time.time()
        
        if last_activity:
            idle_time = current_time - last_activity
            from django.conf import settings
            session_timeout = settings.SESSION_COOKIE_AGE
            
            if idle_time > session_timeout:
                logout(request)
                request.session['session_expired'] = True
                
                if request.headers.get('x-requested-with') == 'XMLHttpRequest':
                    return JsonResponse({
                        'session_expired': True,
                        'redirect_url': reverse('login') + '?session_expired=true'
                    }, status=401)
                
                return redirect(reverse('login') + '?session_expired=true')
        
        return view_func(request, *args, **kwargs)
    return _wrapped_view