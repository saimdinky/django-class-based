"""
Permissions URL configuration for the Django auth starter project.
"""

from django.urls import path
from . import views

app_name = 'permissions'

urlpatterns = [
    path('', views.ListPermissionsView.as_view(), name='list_permissions'),
    path('<int:permission_id>', views.PermissionDetailView.as_view(), name='get_permission'),
]
