"""
Roles URL configuration for the Django auth starter project.
"""

from django.urls import path
from . import views

app_name = 'roles'

urlpatterns = [
    path('', views.ListRolesView.as_view(), name='list_roles'),
    path('<int:role_id>', views.RoleDetailView.as_view(), name='get_role'),
    path('<int:role_id>/permissions', views.ManageRolePermissionsView.as_view(), name='manage_role_permissions'),
]
