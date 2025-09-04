"""
Authentication URL configuration for the Django auth starter project.
Defines API endpoints for authentication operations.
"""

from django.urls import path
from . import views

app_name = 'authentication'

urlpatterns = [
    path('login', views.LoginView.as_view(), name='login'),
    path('register', views.RegisterView.as_view(), name='register'),
    path('profile', views.ProfileView.as_view(), name='profile'),
    path('change-password', views.ChangePasswordView.as_view(), name='change_password'),
    path('refresh-token', views.RefreshTokenView.as_view(), name='refresh_token'),
]
