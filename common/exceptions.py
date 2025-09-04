"""
Custom exception handling for the Django auth starter project.
Provides consistent error responses similar to NestJS exception handling.
"""

import logging
from rest_framework.views import exception_handler
from rest_framework.response import Response
from rest_framework import status
from django.core.exceptions import ValidationError
from django.http import Http404


logger = logging.getLogger(__name__)


def custom_exception_handler(exc, context):
    """
    Custom exception handler that provides consistent error responses.
    Similar to NestJS exception filters.
    """
    
    # Call REST framework's default exception handler first
    response = exception_handler(exc, context)
    
    # Get request information for logging
    request = context.get('request')
    view = context.get('view')
    
    if response is not None:
        # Log the exception
        logger.error(
            f"Exception in {request.method if request else 'Unknown'} "
            f"{request.path if request else 'Unknown'}: "
            f"{type(exc).__name__}: {str(exc)}",
            exc_info=True
        )
        
        # Customize the response format
        custom_response_data = {
            'error': get_error_message(exc),
            'message': get_user_friendly_message(exc),
            'status_code': response.status_code,
            'timestamp': response.get('Date', ''),
        }
        
        # Add validation errors if present
        if hasattr(response, 'data') and isinstance(response.data, dict):
            if 'non_field_errors' in response.data:
                custom_response_data['details'] = response.data['non_field_errors']
            elif any(key in response.data for key in ['email', 'password', 'name']):
                custom_response_data['validation_errors'] = response.data
        
        response.data = custom_response_data
    
    else:
        # Handle exceptions that DRF doesn't handle
        if isinstance(exc, ValidationError):
            response = Response(
                {
                    'error': 'Validation Error',
                    'message': str(exc),
                    'status_code': status.HTTP_400_BAD_REQUEST,
                },
                status=status.HTTP_400_BAD_REQUEST
            )
        
        elif isinstance(exc, Http404):
            response = Response(
                {
                    'error': 'Not Found',
                    'message': 'The requested resource was not found.',
                    'status_code': status.HTTP_404_NOT_FOUND,
                },
                status=status.HTTP_404_NOT_FOUND
            )
        
        else:
            # Log unexpected exceptions
            logger.error(
                f"Unhandled exception in {request.method if request else 'Unknown'} "
                f"{request.path if request else 'Unknown'}: "
                f"{type(exc).__name__}: {str(exc)}",
                exc_info=True
            )
            
            response = Response(
                {
                    'error': 'Internal Server Error',
                    'message': 'An unexpected error occurred. Please try again later.',
                    'status_code': status.HTTP_500_INTERNAL_SERVER_ERROR,
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    return response


def get_error_message(exc):
    """Get the error type name"""
    return exc.__class__.__name__


def get_user_friendly_message(exc):
    """Get a user-friendly error message"""
    error_messages = {
        'ValidationError': 'Please check your input and try again.',
        'AuthenticationFailed': 'Invalid credentials provided.',
        'NotAuthenticated': 'Authentication required to access this resource.',
        'PermissionDenied': 'You do not have permission to perform this action.',
        'NotFound': 'The requested resource was not found.',
        'MethodNotAllowed': 'This method is not allowed for this endpoint.',
        'Throttled': 'Too many requests. Please try again later.',
    }
    
    error_name = exc.__class__.__name__
    return error_messages.get(error_name, str(exc))


class CustomValidationError(Exception):
    """Custom validation error for business logic validation"""
    
    def __init__(self, message, code=None):
        self.message = message
        self.code = code
        super().__init__(self.message)


class BusinessLogicError(Exception):
    """Custom exception for business logic errors"""
    
    def __init__(self, message, code=None):
        self.message = message
        self.code = code
        super().__init__(self.message)


class AuthenticationError(Exception):
    """Custom authentication error"""
    
    def __init__(self, message, code=None):
        self.message = message
        self.code = code
        super().__init__(self.message)


class AuthorizationError(Exception):
    """Custom authorization error"""
    
    def __init__(self, message, code=None):
        self.message = message
        self.code = code
        super().__init__(self.message)
