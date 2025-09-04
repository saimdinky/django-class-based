"""
User model for the Django class-based views project.
Comprehensive user model with role-based access control and authentication.
"""

from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.contrib.auth.base_user import BaseUserManager
from django.db import models
from django.core.validators import EmailValidator
from common.models import BaseModel


class UserManager(BaseUserManager):
    """Custom user manager for the User model"""
    
    def create_user(self, email, password=None, **extra_fields):
        """Create and return a regular user with email and password"""
        if not email:
            raise ValueError('The Email field must be set')
        
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        """Create and return a superuser with email and password"""
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('enable', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(email, password, **extra_fields)

    def active(self):
        """Return only active users"""
        return self.filter(deleted=False, enable=True)

    def by_email(self, email):
        """Get user by email"""
        return self.filter(email=email).first()


class User(AbstractBaseUser, PermissionsMixin, BaseModel):
    """
    Custom User model that extends Django's AbstractBaseUser and BaseModel.
    Equivalent to the NestJS User entity.
    """
    
    name = models.CharField(
        max_length=100,
        null=False,
        blank=False,
        help_text="Full name of the user"
    )
    
    email = models.EmailField(
        max_length=100,
        unique=True,
        null=False,
        blank=False,
        validators=[EmailValidator()],
        help_text="Email address (used for login)"
    )
    
    # Note: password field is inherited from AbstractBaseUser
    
    roles = models.ManyToManyField(
        'roles.Role',
        through='UserRole',
        related_name='users',
        blank=True,
        help_text="Roles assigned to this user"
    )
    
    # Django required fields
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    
    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name']

    class Meta:
        db_table = 'users'
        verbose_name = 'User'
        verbose_name_plural = 'Users'
        indexes = [
            models.Index(fields=['email']),
            models.Index(fields=['name']),
        ]

    def __str__(self):
        return f"{self.name} ({self.email})"

    def __repr__(self):
        return f"User(id={self.id}, name='{self.name}', email='{self.email}')"

    @property
    def is_enabled(self):
        """Check if user is enabled and not deleted"""
        return self.enable and not self.deleted and self.is_active

    def add_role(self, role):
        """Add a role to this user"""
        if not self.roles.filter(id=role.id).exists():
            self.roles.add(role)

    def remove_role(self, role):
        """Remove a role from this user"""
        self.roles.remove(role)

    def has_role(self, role_name):
        """Check if user has a specific role"""
        return self.roles.filter(name=role_name).exists()

    def get_permissions(self):
        """Get all permissions for this user through their roles"""
        permissions = {}
        for role in self.roles.prefetch_related('permissions').all():
            for permission in role.permissions.all():
                permissions[permission.url] = {
                    'role_id': role.id,
                    'role_name': role.name,
                    'permission': {
                        'id': permission.id,
                        'name': permission.name,
                        'url': permission.url,
                        'regex': permission.regex,
                    }
                }
        return permissions

    def has_permission(self, permission_name):
        """Check if user has a specific permission through their roles"""
        return any(
            role.has_permission(permission_name)
            for role in self.roles.all()
        )

    def get_role_names(self):
        """Get list of role names for this user"""
        return list(self.roles.values_list('name', flat=True))


class UserRole(BaseModel):
    """
    Junction table for User-Role many-to-many relationship.
    Equivalent to the NestJS user_roles junction table.
    """
    
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        db_column='user_id'
    )
    
    role = models.ForeignKey(
        'roles.Role',
        on_delete=models.CASCADE,
        db_column='role_id'
    )

    class Meta:
        db_table = 'user_roles'
        unique_together = ('user', 'role')
        verbose_name = 'User Role'
        verbose_name_plural = 'User Roles'

    def __str__(self):
        return f"{self.user.name} - {self.role.name}"