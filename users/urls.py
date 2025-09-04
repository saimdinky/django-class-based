"""
Users URL configuration for the Django auth starter project.
"""

from django.urls import path
from . import views

app_name = 'users'

urlpatterns = [
    path('', views.ListUsersView.as_view(), name='list_users'),
    path('<int:user_id>', views.UserDetailView.as_view(), name='get_user'),
    path('<int:user_id>/roles', views.ManageUserRolesView.as_view(), name='manage_user_roles'),
]
