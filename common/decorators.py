"""
Custom decorators for the Django class-based views project.
Provides comprehensive decorators for authentication, authorization, and validation.
"""

from functools import wraps
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny


def public_endpoint(view_func):
    """
    Decorator to mark an endpoint as public (no authentication required).
    """
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        return view_func(*args, **kwargs)
    
    # Mark the function as public
    wrapper.is_public = True
    wrapper.permission_classes = [AllowAny]
    return wrapper


def require_roles(*required_roles):
    """
    Decorator to require specific roles for accessing an endpoint.
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(self, request, *args, **kwargs):
            if not request.user.is_authenticated:
                return Response(
                    {
                        'error': 'Authentication required',
                        'message': 'You must be logged in to access this resource.',
                        'status_code': status.HTTP_401_UNAUTHORIZED
                    },
                    status=status.HTTP_401_UNAUTHORIZED
                )
            
            user_roles = request.user.get_role_names()
            
            if not any(role in user_roles for role in required_roles):
                return Response(
                    {
                        'error': 'Insufficient permissions',
                        'message': f'Required roles: {", ".join(required_roles)}',
                        'status_code': status.HTTP_403_FORBIDDEN
                    },
                    status=status.HTTP_403_FORBIDDEN
                )
            
            return view_func(self, request, *args, **kwargs)
        
        wrapper.required_roles = required_roles
        return wrapper
    
    return decorator


def require_permissions(*required_permissions):
    """
    Decorator to require specific permissions for accessing an endpoint.
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(self, request, *args, **kwargs):
            if not request.user.is_authenticated:
                return Response(
                    {
                        'error': 'Authentication required',
                        'message': 'You must be logged in to access this resource.',
                        'status_code': status.HTTP_401_UNAUTHORIZED
                    },
                    status=status.HTTP_401_UNAUTHORIZED
                )
            
            user_permissions = request.user.get_permissions()
            user_permission_names = [
                perm['permission']['name'] 
                for perm in user_permissions.values()
            ]
            
            if not any(perm in user_permission_names for perm in required_permissions):
                return Response(
                    {
                        'error': 'Insufficient permissions',
                        'message': f'Required permissions: {", ".join(required_permissions)}',
                        'status_code': status.HTTP_403_FORBIDDEN
                    },
                    status=status.HTTP_403_FORBIDDEN
                )
            
            return view_func(self, request, *args, **kwargs)
        
        wrapper.required_permissions = required_permissions
        return wrapper
    
    return decorator


def log_activity(activity_type):
    """
    Decorator to log user activities and system events.
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(self, request, *args, **kwargs):
            import logging
            logger = logging.getLogger(__name__)
            
            # Log before execution
            user_info = f"User {request.user.id} ({request.user.email})" if request.user.is_authenticated else "Anonymous user"
            logger.info(f"{activity_type}: {user_info} - {request.method} {request.path}")
            
            try:
                response = view_func(self, request, *args, **kwargs)
                
                # Log successful completion
                logger.info(f"{activity_type} completed successfully for {user_info}")
                return response
                
            except Exception as e:
                # Log errors
                logger.error(f"{activity_type} failed for {user_info}: {str(e)}")
                raise
        
        return wrapper
    
    return decorator


def validate_request_data(*required_fields):
    """
    Decorator to validate required fields in request data.
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(self, request, *args, **kwargs):
            # Check if request has data
            if not hasattr(request, 'data') or not request.data:
                return Response(
                    {
                        'error': 'Validation Error',
                        'message': 'Request body is required.',
                        'status_code': status.HTTP_400_BAD_REQUEST
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Check required fields
            missing_fields = []
            for field in required_fields:
                if field not in request.data or not request.data[field]:
                    missing_fields.append(field)
            
            if missing_fields:
                return Response(
                    {
                        'error': 'Validation Error',
                        'message': f'Missing required fields: {", ".join(missing_fields)}',
                        'missing_fields': missing_fields,
                        'status_code': status.HTTP_400_BAD_REQUEST
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            return view_func(self, request, *args, **kwargs)
        
        return wrapper
    
    return decorator
