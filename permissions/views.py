"""
Permissions views for the Django auth starter project.
Placeholder views for permission management endpoints.
"""

from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status


class ListPermissionsView(APIView):
    """List all permissions (placeholder)"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        return Response({'message': 'Permissions endpoint - coming soon'}, status=status.HTTP_200_OK)


class PermissionDetailView(APIView):
    """Get permission by ID (placeholder)"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request, permission_id):
        return Response({'message': f'Get permission {permission_id} - coming soon'}, status=status.HTTP_200_OK)