#!/usr/bin/env python3
"""
Simple test for custom logging without Django setup
"""

import sys
import os
from pathlib import Path

# Add project to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# Test the logging without Django
from common.logging import get_logger, ContextLogger

def test_basic_logging():
    """Test basic logging functionality"""
    print("🎯 Testing Custom Logger...")
    
    # Create logger instance
    logger = get_logger("test_module")
    
    print("\n📋 Basic Logging:")
    logger.debug("This is a debug message")
    logger.info("This is an info message")
    logger.success("This is a success message")
    logger.warning("This is a warning message")
    logger.error("This is an error message")
    
    print("\n🚀 Specialized Logging:")
    logger.user_action("Test action", "User performed some action")
    logger.security_event("Test security", "Security event occurred")
    logger.database_operation("SELECT", "users", "Test database operation")
    logger.performance("Test operation", 0.123)
    
    print("\n✅ Logging test completed!")

if __name__ == "__main__":
    test_basic_logging()
