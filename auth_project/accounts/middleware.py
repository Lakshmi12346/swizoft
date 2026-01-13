import time
from django.contrib.auth import logout
from django.shortcuts import redirect
from django.urls import reverse
from django.utils import timezone  # ADD THIS IMPORT
from django.conf import settings
import logging

logger = logging.getLogger(__name__)


class SessionTimeoutMiddleware:
    """Middleware to handle session timeout."""
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        # Skip for session-status endpoint to avoid infinite redirects
        if request.path == reverse('session-status'):
            return self.get_response(request)
        
        # Skip for non-authenticated users
        if not request.user.is_authenticated:
            return self.get_response(request)
        
        # Skip for certain paths
        excluded_paths = [
            reverse('login'),
            reverse('logout'),
            reverse('extend-session'),
            '/admin/login/',
        ]
        
        if request.path in excluded_paths:
            return self.get_response(request)
        
        # Check session timeout
        last_activity = request.session.get('last_activity')
        current_time = time.time()
        
        if last_activity:
            # Calculate idle time
            idle_time = current_time - last_activity
            
            if idle_time > settings.SESSION_COOKIE_AGE:
                # Session expired
                logger.info(f"Session expired for user {request.user.email}")
                logout(request)
                request.session['session_expired'] = True
                
                # For AJAX requests, return JSON response
                if request.headers.get('x-requested-with') == 'XMLHttpRequest':
                    from django.http import JsonResponse
                    return JsonResponse({
                        'session_expired': True,
                        'redirect_url': reverse('login') + '?session_expired=true'
                    }, status=401)
                
                # For regular requests, redirect to login
                return redirect(reverse('login') + '?session_expired=true')
        
        # Update last activity timestamp
        request.session['last_activity'] = current_time
        
        # Update user's last activity in database
        if request.user.is_authenticated:
            from .models import User
            User.objects.filter(id=request.user.id).update(last_activity=timezone.now())
        
        response = self.get_response(request)
        return response