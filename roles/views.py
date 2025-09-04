"""
Roles views for the Django auth starter project.
Placeholder views for role management endpoints.
"""

from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status


class ListRolesView(APIView):
    """List all roles (placeholder)"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        return Response({'message': 'Roles endpoint - coming soon'}, status=status.HTTP_200_OK)


class RoleDetailView(APIView):
    """Get role by ID (placeholder)"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request, role_id):
        return Response({'message': f'Get role {role_id} - coming soon'}, status=status.HTTP_200_OK)


class ManageRolePermissionsView(APIView):
    """Manage role permissions (placeholder)"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request, role_id):
        return Response({'message': f'Get permissions for role {role_id} - coming soon'}, status=status.HTTP_200_OK)
    
    def post(self, request, role_id):
        return Response({'message': f'Add permission to role {role_id} - coming soon'}, status=status.HTTP_200_OK)
    
    def delete(self, request, role_id):
        return Response({'message': f'Remove permission from role {role_id} - coming soon'}, status=status.HTTP_200_OK)