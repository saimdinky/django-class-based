"""
Custom logging system for Django Class-Based Views project.
Provides structured logging with user context, IP tracking, and file/line information.
Features emojis for better visual experience and debugging capabilities.
"""

import logging
import inspect
import traceback
from typing import Optional, Dict, Any, Union
from datetime import datetime
from contextvars import ContextVar
from django.http import HttpRequest
from rest_framework.request import Request


# Context variables for request tracking
current_request: ContextVar[Optional[Union[HttpRequest, Request]]] = ContextVar(
    'current_request', default=None
)
current_user_id: ContextVar[Optional[int]] = ContextVar('current_user_id', default=None)
current_user_email: ContextVar[Optional[str]] = ContextVar('current_user_email', default=None)
current_ip: ContextVar[Optional[str]] = ContextVar('current_ip', default=None)


# Simple emoji formatter that doesn't cause circular imports
class SimpleEmojiFormatter(logging.Formatter):
    """Simple emoji formatter without Django dependencies"""
    
    EMOJI_MAP = {
        'DEBUG': '🔍',
        'INFO': '📋', 
        'WARNING': '⚠️',
        'ERROR': '❌',
        'CRITICAL': '🚨',
    }
    
    def format(self, record):
        emoji = self.EMOJI_MAP.get(record.levelname, '📝')
        record.emoji = emoji
        return super().format(record)


class ContextLogger:
    """
    Custom logger class that provides easy-to-use logging with automatic context.
    Similar to NestJS Logger service.
    """
    
    def __init__(self, name: str = None):
        """Initialize logger with optional name"""
        if name is None:
            # Get the calling module name automatically
            frame = inspect.currentframe().f_back
            name = frame.f_globals.get('__name__', 'unknown')
        
        self.logger = logging.getLogger(name)
        self._setup_logger()
    
    def _setup_logger(self):
        """Setup logger with custom formatter if not already configured"""
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(SimpleEmojiFormatter(
                '%(emoji)s [%(levelname)s] | 📅 %(asctime)s | 📍 %(module)s:%(funcName)s:%(lineno)d | 💬 %(message)s'
            ))
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.DEBUG)
    
    def debug(self, message: str, extra: Dict[str, Any] = None):
        """Log debug message with emoji 🔍"""
        self.logger.debug(f"🔍 {message}", extra=extra or {})
    
    def info(self, message: str, extra: Dict[str, Any] = None):
        """Log info message with emoji 📋"""
        self.logger.info(f"ℹ️ {message}", extra=extra or {})
    
    def success(self, message: str, extra: Dict[str, Any] = None):
        """Log success message with emoji ✅"""
        self.logger.info(f"✅ {message}", extra=extra or {})
    
    def warning(self, message: str, extra: Dict[str, Any] = None):
        """Log warning message with emoji ⚠️"""
        self.logger.warning(f"⚠️ {message}", extra=extra or {})
    
    def error(self, message: str, error: Exception = None, extra: Dict[str, Any] = None):
        """Log error message with emoji ❌"""
        if error:
            self.logger.error(f"❌ {message}: {str(error)}", exc_info=error, extra=extra or {})
        else:
            self.logger.error(f"❌ {message}", extra=extra or {})
    
    def critical(self, message: str, error: Exception = None, extra: Dict[str, Any] = None):
        """Log critical message with emoji 🚨"""
        if error:
            self.logger.critical(f"🚨 {message}: {str(error)}", exc_info=error, extra=extra or {})
        else:
            self.logger.critical(f"🚨 {message}", extra=extra or {})
    
    def api_request(self, method: str, path: str, status_code: int = None, duration: float = None):
        """Log API request with specific formatting"""
        parts = [f"🚀 API Request: {method} {path}"]
        if status_code:
            emoji = "✅" if 200 <= status_code < 400 else "⚠️" if status_code < 500 else "❌"
            parts.append(f"{emoji} Status: {status_code}")
        if duration:
            parts.append(f"⏱️ Duration: {duration:.3f}s")
        
        self.logger.info(" | ".join(parts))
    
    def api_response(self, status_code: int, message: str = None):
        """Log API response with status-based emoji"""
        emoji = "✅" if 200 <= status_code < 400 else "⚠️" if status_code < 500 else "❌"
        msg = f"{emoji} API Response: {status_code}"
        if message:
            msg += f" - {message}"
        self.logger.info(msg)
    
    def user_action(self, action: str, details: str = None):
        """Log user actions with user emoji"""
        msg = f"👤 User Action: {action}"
        if details:
            msg += f" - {details}"
        self.logger.info(msg)
    
    def security_event(self, event: str, details: str = None):
        """Log security events with security emoji"""
        msg = f"🔒 Security Event: {event}"
        if details:
            msg += f" - {details}"
        self.logger.warning(msg)
    
    def database_operation(self, operation: str, table: str = None, details: str = None):
        """Log database operations with database emoji"""
        msg = f"🗄️ Database: {operation}"
        if table:
            msg += f" on {table}"
        if details:
            msg += f" - {details}"
        self.logger.debug(msg)
    
    def performance(self, operation: str, duration: float, threshold: float = 1.0):
        """Log performance metrics with appropriate emoji"""
        emoji = "🐌" if duration > threshold else "⚡"
        self.logger.info(f"{emoji} Performance: {operation} took {duration:.3f}s")


class RequestContextManager:
    """
    Context manager for automatically setting request context in logs.
    """
    
    def __init__(self, request: Union[HttpRequest, Request]):
        self.request = request
        self.user_id = None
        self.user_email = None
        self.ip = None
    
    def __enter__(self):
        """Set request context when entering"""
        # Extract user information
        if hasattr(self.request, 'user') and self.request.user:
            if hasattr(self.request.user, 'is_authenticated') and self.request.user.is_authenticated:
                self.user_id = getattr(self.request.user, 'id', None)
                self.user_email = getattr(self.request.user, 'email', None)
        
        # Extract IP address
        self.ip = self._get_client_ip()
        
        # Set context variables
        current_request.set(self.request)
        current_user_id.set(self.user_id)
        current_user_email.set(self.user_email)
        current_ip.set(self.ip)
        
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Clear context when exiting"""
        current_request.set(None)
        current_user_id.set(None)
        current_user_email.set(None)
        current_ip.set(None)
    
    def _get_client_ip(self) -> Optional[str]:
        """Extract client IP from request"""
        try:
            # Check for IP in X-Forwarded-For header (proxy/load balancer)
            x_forwarded_for = self.request.META.get('HTTP_X_FORWARDED_FOR')
            if x_forwarded_for:
                return x_forwarded_for.split(',')[0].strip()
            
            # Fall back to direct connection IP
            return self.request.META.get('REMOTE_ADDR', 'Unknown')
        except Exception:
            return 'Unknown'


# Convenience function to get logger instance
def get_logger(name: str = None) -> ContextLogger:
    """
    Get a ContextLogger instance.
    If name is not provided, it will use the calling module's name.
    """
    if name is None:
        # Get the calling module name automatically
        frame = inspect.currentframe().f_back
        name = frame.f_globals.get('__name__', 'unknown')
    
    return ContextLogger(name)


# Note: Don't create global logger instance here to avoid circular imports
# Use get_logger(__name__) in your modules instead
