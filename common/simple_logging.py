"""
Simple logging utility for Django Class-Based Views project.
Provides emoji-enhanced logging without complex middleware integration.
"""

import logging
import inspect
from typing import Optional, Dict, Any


class EmojiLogger:
    """
    Simple logger class with emoji support and context information.
    """
    
    def __init__(self, name: str = None):
        if name is None:
            # Get the calling module name automatically
            frame = inspect.currentframe().f_back
            name = frame.f_globals.get('__name__', 'unknown')
        
        self.logger = logging.getLogger(name)
        self.name = name
    
    def _get_caller_info(self) -> str:
        """Get caller file and line information"""
        try:
            frame = inspect.currentframe().f_back.f_back
            filename = frame.f_code.co_filename.split('/')[-1]
            function_name = frame.f_code.co_name
            line_number = frame.f_lineno
            return f"{filename}:{function_name}():{line_number}"
        except:
            return "unknown:unknown():0"
    
    def _format_message(self, emoji: str, message: str) -> str:
        """Format message with caller info and emoji"""
        caller = self._get_caller_info()
        return f"{emoji} {message} | 📍 {caller}"
    
    def debug(self, message: str, **kwargs):
        """Debug logging with 🔍 emoji"""
        self.logger.debug(self._format_message("🔍", message), **kwargs)
    
    def info(self, message: str, **kwargs):
        """Info logging with 📋 emoji"""
        self.logger.info(self._format_message("📋", message), **kwargs)
    
    def success(self, message: str, **kwargs):
        """Success logging with ✅ emoji"""
        self.logger.info(self._format_message("✅", message), **kwargs)
    
    def warning(self, message: str, **kwargs):
        """Warning logging with ⚠️ emoji"""
        self.logger.warning(self._format_message("⚠️", message), **kwargs)
    
    def error(self, message: str, error: Exception = None, **kwargs):
        """Error logging with ❌ emoji"""
        if error:
            self.logger.error(self._format_message("❌", f"{message}: {str(error)}"), exc_info=error, **kwargs)
        else:
            self.logger.error(self._format_message("❌", message), **kwargs)
    
    def critical(self, message: str, error: Exception = None, **kwargs):
        """Critical logging with 🚨 emoji"""
        if error:
            self.logger.critical(self._format_message("🚨", f"{message}: {str(error)}"), exc_info=error, **kwargs)
        else:
            self.logger.critical(self._format_message("🚨", message), **kwargs)
    
    def user_action(self, action: str, details: str = None, user_email: str = None, user_id: int = None):
        """Log user actions with 👤 emoji"""
        user_info = ""
        if user_email and user_id:
            user_info = f" | 👤 {user_email}({user_id})"
        elif user_email:
            user_info = f" | 👤 {user_email}"
        elif user_id:
            user_info = f" | 👤 User({user_id})"
        
        message = f"User Action: {action}"
        if details:
            message += f" - {details}"
        
        self.logger.info(self._format_message("👤", message) + user_info)
    
    def security_event(self, event: str, details: str = None, ip: str = None):
        """Log security events with 🔒 emoji"""
        ip_info = f" | 🌐 {ip}" if ip else ""
        message = f"Security Event: {event}"
        if details:
            message += f" - {details}"
        
        self.logger.warning(self._format_message("🔒", message) + ip_info)
    
    def api_request(self, method: str, path: str, ip: str = None):
        """Log API requests with 🚀 emoji"""
        ip_info = f" | 🌐 {ip}" if ip else ""
        message = f"API Request: {method} {path}"
        self.logger.info(self._format_message("🚀", message) + ip_info)
    
    def api_response(self, status_code: int, duration: float = None):
        """Log API responses with status-appropriate emoji"""
        emoji = "✅" if 200 <= status_code < 400 else "⚠️" if status_code < 500 else "❌"
        message = f"API Response: {status_code}"
        if duration:
            message += f" | ⏱️ {duration:.3f}s"
        self.logger.info(self._format_message(emoji, message))
    
    def database_operation(self, operation: str, table: str = None, details: str = None):
        """Log database operations with 🗄️ emoji"""
        message = f"Database: {operation}"
        if table:
            message += f" on {table}"
        if details:
            message += f" - {details}"
        self.logger.debug(self._format_message("🗄️", message))
    
    def performance(self, operation: str, duration: float, threshold: float = 1.0):
        """Log performance metrics with ⚡/🐌 emoji"""
        emoji = "🐌" if duration > threshold else "⚡"
        message = f"Performance: {operation} took {duration:.3f}s"
        log_func = self.logger.warning if duration > threshold else self.logger.info
        log_func(self._format_message(emoji, message))


def get_logger(name: str = None) -> EmojiLogger:
    """Get an EmojiLogger instance"""
    if name is None:
        frame = inspect.currentframe().f_back
        name = frame.f_globals.get('__name__', 'unknown')
    return EmojiLogger(name)
