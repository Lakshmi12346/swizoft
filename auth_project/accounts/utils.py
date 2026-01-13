import re
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _


def validate_password_strength(password):
    """
    Validate password strength.
    Returns a dict with 'is_valid' boolean and 'message' string.
    """
    errors = []
    
    # Check length
    if len(password) < 8:
        errors.append(_('Password must be at least 8 characters long.'))
    
    # Check for uppercase
    if not re.search(r'[A-Z]', password):
        errors.append(_('Password must contain at least one uppercase letter.'))
    
    # Check for lowercase
    if not re.search(r'[a-z]', password):
        errors.append(_('Password must contain at least one lowercase letter.'))
    
    # Check for numbers
    if not re.search(r'\d', password):
        errors.append(_('Password must contain at least one number.'))
    
    # Check for special characters
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        errors.append(_('Password must contain at least one special character.'))
    
    if errors:
        return {
            'is_valid': False,
            'message': ' '.join(errors)
        }
    
    return {
        'is_valid': True,
        'message': _('Password is strong.')
    }


def generate_secure_token(length=32):
    """Generate a secure random token."""
    import secrets
    import string
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))