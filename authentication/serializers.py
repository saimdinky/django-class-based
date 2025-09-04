"""
Authentication serializers for the Django class-based views project.
Provides comprehensive serializers for authentication operations with validation.
"""

from rest_framework import serializers
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from users.models import User


class LoginSerializer(serializers.Serializer):
    """
    Serializer for user login with comprehensive validation.
    """
    
    email = serializers.EmailField(
        required=True,
        help_text="User's email address"
    )
    
    password = serializers.CharField(
        required=True,
        write_only=True,
        style={'input_type': 'password'},
        help_text="User's password"
    )

    def validate(self, attrs):
        """Validate login credentials"""
        email = attrs.get('email')
        password = attrs.get('password')

        if email and password:
            # Check if user exists and is active
            try:
                user = User.objects.get(email=email)
                if not user.is_enabled:
                    raise serializers.ValidationError(
                        'User account is disabled or deleted.'
                    )
            except User.DoesNotExist:
                raise serializers.ValidationError(
                    'Invalid credentials.'
                )

            # Authenticate user
            user = authenticate(email=email, password=password)
            if not user:
                raise serializers.ValidationError(
                    'Invalid credentials.'
                )

            attrs['user'] = user
        else:
            raise serializers.ValidationError(
                'Must include email and password.'
            )

        return attrs


class RegisterSerializer(serializers.ModelSerializer):
    """
    Serializer for user registration.
    Equivalent to NestJS RegisterZod schema.
    """
    
    password = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'},
        help_text="User's password (minimum 8 characters)"
    )
    
    password_confirm = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'},
        help_text="Password confirmation"
    )

    class Meta:
        model = User
        fields = ('name', 'email', 'password', 'password_confirm')
        extra_kwargs = {
            'name': {'required': True, 'help_text': "User's full name"},
            'email': {'required': True, 'help_text': "User's email address"},
        }

    def validate_email(self, value):
        """Validate email uniqueness"""
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError(
                'User with this email already exists.'
            )
        return value

    def validate_password(self, value):
        """Validate password strength"""
        try:
            validate_password(value)
        except DjangoValidationError as e:
            raise serializers.ValidationError(list(e.messages))
        return value

    def validate(self, attrs):
        """Validate password confirmation"""
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError({
                'password_confirm': 'Password confirmation does not match.'
            })
        return attrs

    def create(self, validated_data):
        """Create new user"""
        validated_data.pop('password_confirm', None)
        user = User.objects.create_user(**validated_data)
        return user


class ChangePasswordSerializer(serializers.Serializer):
    """
    Serializer for password change.
    Equivalent to NestJS ChangePasswordZod schema.
    """
    
    current_password = serializers.CharField(
        required=True,
        write_only=True,
        style={'input_type': 'password'},
        help_text="Current password"
    )
    
    new_password = serializers.CharField(
        required=True,
        write_only=True,
        style={'input_type': 'password'},
        help_text="New password (minimum 8 characters)"
    )
    
    new_password_confirm = serializers.CharField(
        required=True,
        write_only=True,
        style={'input_type': 'password'},
        help_text="New password confirmation"
    )

    def validate_current_password(self, value):
        """Validate current password"""
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError(
                'Current password is incorrect.'
            )
        return value

    def validate_new_password(self, value):
        """Validate new password strength"""
        try:
            validate_password(value, self.context['request'].user)
        except DjangoValidationError as e:
            raise serializers.ValidationError(list(e.messages))
        return value

    def validate(self, attrs):
        """Validate new password confirmation"""
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError({
                'new_password_confirm': 'New password confirmation does not match.'
            })
        return attrs


class UserProfileSerializer(serializers.ModelSerializer):
    """
    Serializer for user profile information.
    Used for profile endpoint responses.
    """
    
    roles = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ('id', 'name', 'email', 'roles', 'created_at', 'updated_at')
        read_only_fields = ('id', 'created_at', 'updated_at')

    def get_roles(self, obj):
        """Get user roles with permissions"""
        roles_data = []
        for role in obj.roles.prefetch_related('permissions').all():
            permissions_data = []
            for permission in role.permissions.all():
                permissions_data.append({
                    'id': permission.id,
                    'name': permission.name,
                    'url': permission.url,
                    'regex': permission.regex,
                })
            
            roles_data.append({
                'id': role.id,
                'name': role.name,
                'permissions': permissions_data,
            })
        
        return roles_data


class LoginResponseSerializer(serializers.Serializer):
    """
    Serializer for login response.
    Equivalent to NestJS LoginResponseZod schema.
    """
    
    access_token = serializers.CharField(
        help_text="JWT access token"
    )
    
    refresh_token = serializers.CharField(
        help_text="JWT refresh token"
    )
    
    user = UserProfileSerializer(
        help_text="User profile information"
    )

    class Meta:
        fields = ('access_token', 'refresh_token', 'user')
