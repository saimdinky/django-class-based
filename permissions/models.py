"""
Permission model for the Django class-based views project.
Granular permission system for fine-grained access control.
"""

from django.db import models
from common.models import BaseModel, BaseManager


class PermissionManager(BaseManager):
    """Custom manager for Permission model"""
    
    def by_name(self, name):
        """Get permission by name"""
        return self.active().filter(name=name).first()
    
    def by_url(self, url):
        """Get permissions by URL"""
        return self.active().filter(url=url)


class Permission(BaseModel):
    """
    Permission model that defines access control permissions.
    Equivalent to the NestJS Permission entity.
    """
    
    name = models.CharField(
        max_length=255,
        unique=True,
        null=False,
        blank=False,
        help_text="Unique name of the permission"
    )
    
    url = models.CharField(
        max_length=255,
        null=False,
        blank=False,
        help_text="URL pattern this permission applies to"
    )
    
    regex = models.CharField(
        max_length=500,
        null=False,
        blank=False,
        help_text="Regular expression pattern for URL matching"
    )
    
    description = models.TextField(
        blank=True,
        null=True,
        help_text="Description of what this permission allows"
    )

    objects = PermissionManager()

    class Meta:
        db_table = 'permissions'
        verbose_name = 'Permission'
        verbose_name_plural = 'Permissions'
        indexes = [
            models.Index(fields=['name']),
            models.Index(fields=['url']),
        ]

    def __str__(self):
        return f"{self.name} ({self.url})"

    def __repr__(self):
        return f"Permission(id={self.id}, name='{self.name}', url='{self.url}')"