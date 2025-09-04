"""
Common middleware for the Django class-based views project.
Provides logging and rate limiting functionality with comprehensive security features.

This module contains custom middleware classes that enhance the Django request/response cycle:
- LoggingMiddleware: Comprehensive request/response logging
- RateLimitMiddleware: IP-based rate limiting protection
- CORSMiddleware: Additional security headers for API responses
"""

import time
import logging
from typing import Optional, List, Union
from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.utils.deprecation import MiddlewareMixin
from django.conf import settings
from rest_framework import status

from .simple_logging import get_logger

logger = get_logger(__name__)


class LoggingMiddleware(MiddlewareMixin):
    """
    Middleware for logging requests and responses.
    Provides comprehensive request/response logging with performance monitoring.
    
    Features:
    - Comprehensive request/response logging
    - Exception tracking with stack traces  
    - Performance monitoring (request duration)
    - Configurable path exclusions
    - Client IP detection with proxy support
    - Duplicate prevention
    """

    def __init__(self, get_response):
        """Initialize middleware with configurable skip paths."""
        self.get_response = get_response
        self.skip_paths: List[str] = getattr(
            settings, 'LOGGING_SKIP_PATHS', ['/static/', '/media/', '/admin/jsi18n/', '/favicon.ico']
        )
        super().__init__(get_response)

    def process_request(self, request: HttpRequest) -> Optional[HttpResponse]:
        """
        Log incoming requests with timing and client information.
        
        Args:
            request: The incoming HTTP request
            
        Returns:
            None to continue processing
        """
        request.start_time = time.time()
        
        # Skip logging for configured paths
        if self.should_skip_logging(request):
            return None
        
        # Prevent duplicate logging
        if hasattr(request, '_logged_by_custom_middleware'):
            return None
        
        # Get client IP
        client_ip = self.get_client_ip(request)
        
        # Log incoming request
        logger.api_request(request.method, request.path, ip=client_ip)
        
        # Mark as logged
        request._logged_by_custom_middleware = True
        
        return None

    def process_response(self, request: HttpRequest, response: HttpResponse) -> HttpResponse:
        """
        Log outgoing responses with performance metrics.
        
        Args:
            request: The HTTP request
            response: The HTTP response
            
        Returns:
            The response object
        """
        # Only log if we logged the request and haven't logged the response yet
        if (hasattr(request, 'start_time') and 
            hasattr(request, '_logged_by_custom_middleware') and
            not self.should_skip_logging(request) and 
            not hasattr(request, '_response_logged')):
            
            duration = time.time() - request.start_time
            
            # Log response with performance metrics
            logger.api_response(response.status_code, duration)
            
            # Log performance warning for slow requests
            if duration > 1.0:
                logger.performance(f"{request.method} {request.path}", duration)
            
            request._response_logged = True
            
        return response

    def process_exception(self, request: HttpRequest, exception: Exception) -> Optional[HttpResponse]:
        """
        Log exceptions with detailed context.
        
        Args:
            request: The HTTP request that caused the exception
            exception: The exception that was raised
            
        Returns:
            None to continue normal exception handling
        """
        if not self.should_skip_logging(request) and not hasattr(request, '_exception_logged'):
            client_ip = self.get_client_ip(request)
            logger.error(f"Unhandled exception in {request.method} {request.path}", error=exception)
            request._exception_logged = True
        return None

    def should_skip_logging(self, request: HttpRequest) -> bool:
        """
        Determine if logging should be skipped for this request.
        
        Args:
            request: The HTTP request to check
            
        Returns:
            True if logging should be skipped, False otherwise
        """
        return any(request.path.startswith(path) for path in self.skip_paths)

    def get_client_ip(self, request: HttpRequest) -> str:
        """
        Get client IP address with proxy support.
        
        Args:
            request: The HTTP request
            
        Returns:
            The client's IP address
        """
        # Check for IP in X-Forwarded-For header (proxy/load balancer)
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            # Take the first IP in the chain
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            # Fall back to direct connection IP
            ip = request.META.get('REMOTE_ADDR', 'Unknown')
        return ip

    def _get_user_info(self, request: HttpRequest) -> str:
        """
        Get user information for logging.
        
        Args:
            request: The HTTP request
            
        Returns:
            User information string
        """
        if hasattr(request, 'user') and request.user.is_authenticated:
            return f"User: {request.user.email} (ID: {request.user.id})"
        return "Anonymous"


class RateLimitMiddleware(MiddlewareMixin):
    """
    Rate limiting middleware for API protection.
    
    Features:
    - IP-based rate limiting with Redis/cache backend
    - Configurable limits and time windows
    - Path-based exclusions
    - Detailed logging and monitoring
    - Graceful error handling
    """

    def __init__(self, get_response):
        """Initialize rate limiting middleware with configuration."""
        self.get_response = get_response
        
        # Configuration with defaults
        self.rate_limit_ttl: int = getattr(settings, 'RATE_LIMIT_TTL', 60)
        self.rate_limit_limit: int = getattr(settings, 'RATE_LIMIT_LIMIT', 100)
        self.skip_paths: List[str] = getattr(
            settings, 'RATE_LIMIT_SKIP_PATHS', 
            ['/static/', '/media/', '/admin/', '/health/']
        )
        
        # Validate configuration
        if self.rate_limit_ttl <= 0 or self.rate_limit_limit <= 0:
            raise ImproperlyConfigured(
                "RATE_LIMIT_TTL and RATE_LIMIT_LIMIT must be positive integers"
            )
        
        super().__init__(get_response)

    def process_request(self, request: HttpRequest) -> Optional[HttpResponse]:
        """
        Check rate limits before processing request.
        
        Args:
            request: The incoming HTTP request
            
        Returns:
            JsonResponse with 429 status if rate limit exceeded, None otherwise
        """
        # Skip rate limiting for configured paths
        if self.should_skip_rate_limiting(request):
            return None

        client_ip = self.get_client_ip(request)
        
        try:
            # Check and update rate limit
            if self._is_rate_limited(client_ip):
                return self._create_rate_limit_response(client_ip, request)
        except Exception as e:
            # Log cache errors but don't block requests
            logger.error(f"Rate limiting error for {client_ip}: {e}")
            
        return None

    def _is_rate_limited(self, client_ip: str) -> bool:
        """
        Check if client IP has exceeded rate limit.
        
        Args:
            client_ip: The client's IP address
            
        Returns:
            True if rate limit exceeded, False otherwise
        """
        cache_key = f"rate_limit:{client_ip}"
        
        try:
            # Get current request count
            current_requests = cache.get(cache_key, 0)
            
            if current_requests >= self.rate_limit_limit:
                logger.security_event(
                    "Rate limit exceeded",
                    f"IP: {client_ip}, Requests: {current_requests}/{self.rate_limit_limit} in {self.rate_limit_ttl}s"
                )
                return True
            
            # Increment request count
            cache.set(cache_key, current_requests + 1, timeout=self.rate_limit_ttl)
            return False
            
        except Exception as e:
            logger.error("Cache operation failed for rate limiting", error=e)
            # Fail open - don't block requests if cache is down
            return False

    def _create_rate_limit_response(self, client_ip: str, request: HttpRequest) -> JsonResponse:
        """
        Create rate limit exceeded response.
        
        Args:
            client_ip: The client's IP address
            request: The HTTP request
            
        Returns:
            JsonResponse with rate limit error
        """
        # Calculate reset time
        cache_key = f"rate_limit:{client_ip}"
        ttl = cache.ttl(cache_key) if hasattr(cache, 'ttl') else self.rate_limit_ttl
        
        response_data = {
            'error': 'Rate limit exceeded',
            'message': f'Too many requests. Limit: {self.rate_limit_limit} per {self.rate_limit_ttl}s',
            'status_code': status.HTTP_429_TOO_MANY_REQUESTS,
            'retry_after': ttl if ttl > 0 else self.rate_limit_ttl
        }
        
        response = JsonResponse(response_data, status=status.HTTP_429_TOO_MANY_REQUESTS)
        
        # Add rate limit headers
        response['X-RateLimit-Limit'] = str(self.rate_limit_limit)
        response['X-RateLimit-Window'] = str(self.rate_limit_ttl)
        response['Retry-After'] = str(response_data['retry_after'])
        
        return response

    def should_skip_rate_limiting(self, request: HttpRequest) -> bool:
        """
        Determine if rate limiting should be skipped.
        
        Args:
            request: The HTTP request to check
            
        Returns:
            True if rate limiting should be skipped, False otherwise
        """
        return any(request.path.startswith(path) for path in self.skip_paths)

    def get_client_ip(self, request: HttpRequest) -> str:
        """
        Get client IP address with proxy support.
        
        Args:
            request: The HTTP request
            
        Returns:
            The client's IP address
        """
        # Check for IP in X-Forwarded-For header (proxy/load balancer)
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            # Take the first IP in the chain
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            # Fall back to direct connection IP
            ip = request.META.get('REMOTE_ADDR', 'Unknown')
        return ip


class SecurityHeadersMiddleware(MiddlewareMixin):
    """
    Security headers middleware for enhanced API security.
    Works alongside django-cors-headers to add comprehensive security headers.
    
    Features:
    - API versioning headers
    - Content security headers
    - XSS protection
    - Clickjacking protection
    - Content type sniffing protection
    """

    def __init__(self, get_response):
        """Initialize security headers middleware."""
        self.get_response = get_response
        self.api_version: str = getattr(settings, 'API_VERSION', '1.0.0')
        super().__init__(get_response)

    def process_response(self, request: HttpRequest, response: HttpResponse) -> HttpResponse:
        """
        Add security headers to responses.
        
        Args:
            request: The HTTP request
            response: The HTTP response
            
        Returns:
            The response with added security headers
        """
        # Add security headers for all API responses
        if request.path.startswith('/api/'):
            self._add_api_headers(response)
        
        # Add general security headers
        self._add_security_headers(response)
        
        return response

    def _add_api_headers(self, response: HttpResponse) -> None:
        """
        Add API-specific headers.
        
        Args:
            response: The HTTP response to modify
        """
        response['X-API-Version'] = self.api_version
        response['X-Content-Type-Options'] = 'nosniff'
        response['Cache-Control'] = 'no-cache, no-store, must-revalidate'

    def _add_security_headers(self, response: HttpResponse) -> None:
        """
        Add general security headers.
        
        Args:
            response: The HTTP response to modify
        """
        # Prevent clickjacking
        if 'X-Frame-Options' not in response:
            response['X-Frame-Options'] = 'DENY'
        
        # XSS protection
        if 'X-XSS-Protection' not in response:
            response['X-XSS-Protection'] = '1; mode=block'
        
        # Referrer policy
        if 'Referrer-Policy' not in response:
            response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
