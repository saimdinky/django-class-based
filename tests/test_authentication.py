"""
Tests for authentication functionality.
"""

import pytest
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework import status
from users.models import User


class AuthenticationTestCase(TestCase):
    """Test authentication endpoints"""

    def setUp(self):
        """Set up test data"""
        self.client = APIClient()
        self.user_data = {
            'name': 'Test User',
            'email': 'test@example.com',
            'password': 'TestPassword123!',
            'password_confirm': 'TestPassword123!'
        }
        self.login_data = {
            'email': 'test@example.com',
            'password': 'TestPassword123!'
        }

    def test_user_registration(self):
        """Test user registration"""
        url = reverse('authentication:register')
        response = self.client.post(url, self.user_data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('access_token', response.data)
        self.assertIn('user', response.data)
        self.assertEqual(response.data['user']['email'], self.user_data['email'])

    def test_user_login(self):
        """Test user login"""
        # First create a user
        User.objects.create_user(
            name=self.user_data['name'],
            email=self.user_data['email'],
            password=self.user_data['password']
        )
        
        url = reverse('authentication:login')
        response = self.client.post(url, self.login_data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access_token', response.data)
        self.assertIn('user', response.data)

    def test_get_profile_authenticated(self):
        """Test getting profile when authenticated"""
        # Create and authenticate user
        user = User.objects.create_user(
            name=self.user_data['name'],
            email=self.user_data['email'],
            password=self.user_data['password']
        )
        
        # Login to get token
        login_url = reverse('authentication:login')
        login_response = self.client.post(login_url, self.login_data, format='json')
        token = login_response.data['access_token']
        
        # Get profile
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')
        profile_url = reverse('authentication:profile')
        response = self.client.get(profile_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['email'], user.email)

    def test_get_profile_unauthenticated(self):
        """Test getting profile when not authenticated"""
        url = reverse('authentication:profile')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_health_check(self):
        """Test health check endpoint"""
        url = reverse('common:health_check')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['status'], 'healthy')
