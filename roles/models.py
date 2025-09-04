"""
Role model for the Django auth starter project.
Equivalent to the NestJS Role entity.
"""

from django.db import models
from common.models import BaseModel, BaseManager


class RoleManager(BaseManager):
    """Custom manager for Role model"""
    
    def by_name(self, name):
        """Get role by name"""
        return self.active().filter(name=name).first()
    
    def with_permissions(self):
        """Get roles with their permissions prefetched"""
        return self.active().prefetch_related('permissions')


class Role(BaseModel):
    """
    Role model that defines user roles and their permissions.
    Equivalent to the NestJS Role entity.
    """
    
    name = models.CharField(
        max_length=255,
        unique=True,
        null=False,
        blank=False,
        help_text="Unique name of the role"
    )
    
    description = models.TextField(
        blank=True,
        null=True,
        help_text="Description of the role and its purpose"
    )
    
    permissions = models.ManyToManyField(
        'permissions.Permission',
        through='RolePermission',
        related_name='roles',
        blank=True,
        help_text="Permissions granted to this role"
    )

    objects = RoleManager()

    class Meta:
        db_table = 'roles'
        verbose_name = 'Role'
        verbose_name_plural = 'Roles'
        indexes = [
            models.Index(fields=['name']),
        ]

    def __str__(self):
        return self.name

    def __repr__(self):
        return f"Role(id={self.id}, name='{self.name}')"

    def add_permission(self, permission):
        """Add a permission to this role"""
        if not self.permissions.filter(id=permission.id).exists():
            self.permissions.add(permission)

    def remove_permission(self, permission):
        """Remove a permission from this role"""
        self.permissions.remove(permission)

    def has_permission(self, permission_name):
        """Check if role has a specific permission"""
        return self.permissions.filter(name=permission_name).exists()

    def get_permission_urls(self):
        """Get all URL patterns this role has access to"""
        return list(self.permissions.values_list('url', flat=True))


class RolePermission(BaseModel):
    """
    Junction table for Role-Permission many-to-many relationship.
    Equivalent to the NestJS role_permission junction table.
    """
    
    role = models.ForeignKey(
        Role,
        on_delete=models.CASCADE,
        db_column='role_id'
    )
    
    permission = models.ForeignKey(
        'permissions.Permission',
        on_delete=models.CASCADE,
        db_column='permission_id'
    )

    class Meta:
        db_table = 'role_permission'
        unique_together = ('role', 'permission')
        verbose_name = 'Role Permission'
        verbose_name_plural = 'Role Permissions'

    def __str__(self):
        return f"{self.role.name} - {self.permission.name}"