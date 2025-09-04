"""
Common URL configuration for health checks and utilities.
"""

from django.urls import path
from . import views

app_name = 'common'

urlpatterns = [
    path('', views.HealthCheckView.as_view(), name='health_check'),
]
