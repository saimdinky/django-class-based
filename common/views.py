"""
Common views for the Django class-based views project.
Provides utility endpoints like health checks and system monitoring.
"""

from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
from django.conf import settings
from drf_spectacular.utils import extend_schema

from .simple_logging import get_logger

logger = get_logger(__name__)


class HealthCheckView(APIView):
    """
    Health check endpoint to verify API is running and healthy.
    """
    permission_classes = [AllowAny]

    @extend_schema(
        operation_id='health_check',
        summary='Health check',
        description='Check if the API is running and healthy',
        responses={
            200: {
                'type': 'object',
                'properties': {
                    'status': {'type': 'string'},
                    'message': {'type': 'string'},
                    'version': {'type': 'string'},
                    'environment': {'type': 'string'},
                }
            }
        },
        tags=['Health']
    )
    def get(self, request):
        try:
            # Test database connection
            from django.db import connection
            cursor = connection.cursor()
            cursor.execute("SELECT 1")
            db_status = "connected"
        except Exception as e:
            db_status = "disconnected"
            logger.error("Database health check failed", error=e)
        
        response_data = {
            'status': 'healthy',
            'message': 'Django Class-Based Views API is running',
            'version': '1.0.0',
            'environment': settings.ENVIRONMENT if hasattr(settings, 'ENVIRONMENT') else 'development',
            'database': db_status,
        }
        
        return Response(response_data, status=status.HTTP_200_OK)