"""
Authentication views for the Django class-based views project.
Provides comprehensive authentication endpoints with JWT token management.

This module contains class-based views for user authentication operations:
- LoginView: User login with JWT token generation
- RegisterView: User registration with automatic login
- ProfileView: Retrieve authenticated user profile
- ChangePasswordView: Change user password with validation
- RefreshTokenView: Refresh JWT access tokens
"""

import logging
from typing import Any, Dict
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.request import Request
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from drf_spectacular.utils import extend_schema, OpenApiResponse
from django.contrib.auth import authenticate
from django.db import transaction
from django.core.exceptions import ValidationError as DjangoValidationError

from .serializers import (
    LoginSerializer,
    RegisterSerializer,
    ChangePasswordSerializer,
    UserProfileSerializer,
    LoginResponseSerializer
)
from common.exceptions import AuthenticationError
from common.simple_logging import get_logger


logger = get_logger(__name__)


class LoginView(APIView):
    """
    User login endpoint with JWT token generation.
    
    Provides secure authentication with comprehensive error handling.
    
    Features:
    - Email/password authentication
    - JWT token generation with custom claims
    - Comprehensive error handling
    - Security logging
    """
    permission_classes = [AllowAny]

    @extend_schema(
        operation_id='auth_login',
        summary='User login',
        description='Authenticate user with email/password and return JWT tokens with user profile',
        request=LoginSerializer,
        responses={
            200: OpenApiResponse(
                response=LoginResponseSerializer,
                description='Login successful - returns access token, refresh token, and user profile'
            ),
            400: OpenApiResponse(description='Bad request - validation errors or invalid input'),
            401: OpenApiResponse(description='Unauthorized - invalid credentials or disabled account'),
            429: OpenApiResponse(description='Too many requests - rate limit exceeded'),
        },
        tags=['Authentication']
    )
    def post(self, request: Request) -> Response:
        """
        Authenticate user and return JWT tokens.
        
        Args:
            request: HTTP request containing email and password
            
        Returns:
            Response with access_token, refresh_token, and user data
        """
        try:
            logger.info("User login attempt")
            
            # Validate request data
            serializer = LoginSerializer(data=request.data)
            
            if not serializer.is_valid():
                logger.warning(f"Login validation failed: {serializer.errors}")
                return self._create_validation_error_response(serializer.errors)
            
            user = serializer.validated_data['user']
            
            # Generate JWT tokens with custom claims
            logger.debug("Generating JWT tokens for user")
            tokens = self._generate_user_tokens(user)
            
            # Prepare response data
            response_data = self._prepare_login_response(user, tokens)
            
            logger.user_action("Login successful", f"User: {user.email} (ID: {user.id})", user.email, user.id)
            
            return Response(response_data, status=status.HTTP_200_OK)
            
        except AuthenticationError as e:
            client_ip = self._get_client_ip(request)
            logger.security_event("Authentication failed", str(e), ip=client_ip)
            return self._create_auth_error_response(str(e))
            
        except DjangoValidationError as e:
            logger.warning(f"Validation error: {str(e)}")
            return self._create_validation_error_response({'non_field_errors': [str(e)]})
            
        except Exception as e:
            logger.error("Unexpected login error", error=e)
            return self._create_server_error_response()

    def _generate_user_tokens(self, user) -> Dict[str, str]:
        """
        Generate JWT tokens with custom claims for user.
        
        Args:
            user: Authenticated user instance
            
        Returns:
            Dictionary containing access and refresh tokens
        """
        refresh = RefreshToken.for_user(user)
        access_token = refresh.access_token
        
        # Add custom claims to the token
        access_token['email'] = user.email
        access_token['roles'] = user.get_role_names()
        access_token['permissions'] = user.get_permissions()
        
        return {
            'access_token': str(access_token),
            'refresh_token': str(refresh)
        }

    def _prepare_login_response(self, user, tokens: Dict[str, str]) -> Dict[str, Any]:
        """
        Prepare login response data.
        
        Args:
            user: Authenticated user instance
            tokens: Generated JWT tokens
            
        Returns:
            Complete response data dictionary
        """
        user_serializer = UserProfileSerializer(user)
        
        return {
            'access_token': tokens['access_token'],
            'refresh_token': tokens['refresh_token'],
            'user': user_serializer.data,
            'message': 'Login successful'
        }

    def _create_validation_error_response(self, errors: Dict) -> Response:
        """Create standardized validation error response."""
        return Response(
            {
                'error': 'Validation Error',
                'message': 'Invalid input data provided.',
                'validation_errors': errors,
                'status_code': status.HTTP_400_BAD_REQUEST
            },
            status=status.HTTP_400_BAD_REQUEST
        )

    def _create_auth_error_response(self, message: str) -> Response:
        """Create standardized authentication error response."""
        return Response(
            {
                'error': 'Authentication Failed',
                'message': message,
                'status_code': status.HTTP_401_UNAUTHORIZED
            },
            status=status.HTTP_401_UNAUTHORIZED
        )

    def _create_server_error_response(self) -> Response:
        """Create standardized server error response."""
        return Response(
            {
                'error': 'Internal Server Error',
                'message': 'An unexpected error occurred. Please try again later.',
                'status_code': status.HTTP_500_INTERNAL_SERVER_ERROR
            },
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP address from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', 'Unknown')


class RegisterView(APIView):
    """
    User registration endpoint with automatic login.
    """
    permission_classes = [AllowAny]

    @extend_schema(
        operation_id='auth_register',
        summary='User registration',
        description='Register a new user account and return JWT tokens',
        request=RegisterSerializer,
        responses={
            201: OpenApiResponse(
                response=LoginResponseSerializer,
                description='Registration successful'
            ),
            400: OpenApiResponse(description='Bad request - validation errors'),
            409: OpenApiResponse(description='Conflict - user already exists'),
        },
        tags=['Authentication']
    )
    def post(self, request):
        with RequestContextManager(request):
            try:
                logger.info("User registration attempt")
                
                # Validate request data
                serializer = RegisterSerializer(data=request.data)
                
                if not serializer.is_valid():
                    logger.warning(f"Registration validation failed: {serializer.errors}")
                    return self._create_validation_error_response(serializer.errors)
                
                # Create user with transaction
                with transaction.atomic():
                    logger.database_operation("INSERT", "users", "Creating new user account")
                    user = serializer.save()
                    logger.database_operation("INSERT", "users", f"User created with ID: {user.id}")
                
                # Generate JWT tokens for the new user
                logger.debug("Generating JWT tokens for new user")
                tokens = self._generate_user_tokens(user)
                
                # Prepare response data
                response_data = self._prepare_login_response(user, tokens)
                
                logger.user_action("Registration successful", f"New user: {user.email} (ID: {user.id})")
                
                return Response(response_data, status=status.HTTP_201_CREATED)
                
            except Exception as e:
                logger.error("Registration error occurred", error=e)
                return self._create_server_error_response()


class ProfileView(APIView):
    """
    Get user profile endpoint.
    Equivalent to NestJS AuthController.getProfile method.
    """
    permission_classes = [IsAuthenticated]

    @extend_schema(
        operation_id='auth_profile',
        summary='Get user profile',
        description='Get current user profile information',
        responses={
            200: OpenApiResponse(
                response=UserProfileSerializer,
                description='Profile retrieved successfully'
            ),
            401: OpenApiResponse(description='Unauthorized - authentication required'),
        },
        tags=['Authentication']
    )
    def get(self, request):
        with RequestContextManager(request):
            try:
                logger.info("Profile retrieval requested")
                
                user = request.user
                logger.database_operation("SELECT", "users", f"Retrieving profile for user ID: {user.id}")
                
                serializer = UserProfileSerializer(user)
                
                logger.user_action("Profile retrieved", f"User: {user.email}")
                
                return Response(serializer.data, status=status.HTTP_200_OK)
                
            except Exception as e:
                logger.error("Profile retrieval error", error=e)
                return Response(
                    {
                        'error': 'Profile Error',
                        'message': 'Failed to retrieve profile.',
                        'status_code': status.HTTP_400_BAD_REQUEST
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )


class ChangePasswordView(APIView):
    """
    Change password endpoint.
    Equivalent to NestJS AuthController.changePassword method.
    """
    permission_classes = [IsAuthenticated]

    @extend_schema(
        operation_id='auth_change_password',
        summary='Change password',
        description='Change user password',
        request=ChangePasswordSerializer,
        responses={
            200: OpenApiResponse(description='Password changed successfully'),
            400: OpenApiResponse(description='Bad request - validation errors'),
            401: OpenApiResponse(description='Unauthorized - authentication required'),
        },
        tags=['Authentication']
    )
    def post(self, request):
        try:
            serializer = ChangePasswordSerializer(
                data=request.data,
                context={'request': request}
            )
            
            if not serializer.is_valid():
                logger.warning(f"Change password validation failed: {serializer.errors}")
                return Response(
                    {
                        'error': 'Validation Error',
                        'message': 'Invalid input data.',
                        'validation_errors': serializer.errors,
                        'status_code': status.HTTP_400_BAD_REQUEST
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Change password
            user = request.user
            user.set_password(serializer.validated_data['new_password'])
            user.save(update_fields=['password', 'updated_at'])
            
            logger.info(f"Password changed successfully for user {user.email}")
            
            return Response(
                {
                    'message': 'Password changed successfully.'
                },
                status=status.HTTP_200_OK
            )
            
        except Exception as e:
            logger.error(f"Change password error: {str(e)}", exc_info=True)
            return Response(
                {
                    'error': 'Password Change Failed',
                    'message': 'Failed to change password. Please try again.',
                    'status_code': status.HTTP_400_BAD_REQUEST
                },
                status=status.HTTP_400_BAD_REQUEST
            )


class RefreshTokenView(APIView):
    """
    Refresh JWT token endpoint.
    Additional endpoint for token refresh functionality.
    """
    permission_classes = [AllowAny]

    @extend_schema(
        operation_id='auth_refresh_token',
        summary='Refresh JWT token',
        description='Refresh access token using refresh token',
        responses={
            200: OpenApiResponse(description='Token refreshed successfully'),
            401: OpenApiResponse(description='Unauthorized - invalid refresh token'),
        },
        tags=['Authentication']
    )
    def post(self, request):
        try:
            refresh_token = request.data.get('refresh_token')
            
            if not refresh_token:
                return Response(
                    {
                        'error': 'Validation Error',
                        'message': 'Refresh token is required.',
                        'status_code': status.HTTP_400_BAD_REQUEST
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            try:
                refresh = RefreshToken(refresh_token)
                access_token = refresh.access_token
                
                # Get user and add custom claims
                user = refresh.user if hasattr(refresh, 'user') else None
                if user:
                    access_token['email'] = user.email
                    access_token['roles'] = user.get_role_names()
                    access_token['permissions'] = user.get_permissions()
                
                return Response(
                    {
                        'access_token': str(access_token),
                        'refresh_token': str(refresh),
                    },
                    status=status.HTTP_200_OK
                )
                
            except Exception as token_error:
                logger.warning(f"Invalid refresh token: {str(token_error)}")
                return Response(
                    {
                        'error': 'Invalid Token',
                        'message': 'Invalid or expired refresh token.',
                        'status_code': status.HTTP_401_UNAUTHORIZED
                    },
                    status=status.HTTP_401_UNAUTHORIZED
                )
            
        except Exception as e:
            logger.error(f"Token refresh error: {str(e)}", exc_info=True)
            return Response(
                {
                    'error': 'Token Refresh Failed',
                    'message': 'Failed to refresh token. Please try again.',
                    'status_code': status.HTTP_400_BAD_REQUEST
                },
                status=status.HTTP_400_BAD_REQUEST
            )