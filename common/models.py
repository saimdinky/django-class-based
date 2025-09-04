"""
Common models and base entity for the Django class-based views project.
Provides base functionality and common fields for all models.
"""

from django.db import models
from django.utils import timezone


class BaseModel(models.Model):
    """
    Base model class that provides common fields and functionality
    similar to the NestJS BaseEntity.
    """
    
    id = models.AutoField(primary_key=True)
    created_at = models.DateTimeField(auto_now_add=True, db_column='created_at')
    updated_at = models.DateTimeField(auto_now=True, db_column='updated_at')
    enable = models.BooleanField(default=True)
    deleted = models.BooleanField(default=False)

    class Meta:
        abstract = True
        ordering = ['-created_at']

    def soft_delete(self):
        """Soft delete the record by setting deleted=True"""
        self.deleted = True
        self.save(update_fields=['deleted', 'updated_at'])

    def restore(self):
        """Restore a soft deleted record"""
        self.deleted = False
        self.save(update_fields=['deleted', 'updated_at'])

    def disable(self):
        """Disable the record"""
        self.enable = False
        self.save(update_fields=['enable', 'updated_at'])

    def activate(self):
        """Activate the record"""
        self.enable = True
        self.save(update_fields=['enable', 'updated_at'])

    @property
    def entity_name(self):
        """Return the entity class name"""
        return self.__class__.__name__


class BaseManager(models.Manager):
    """
    Custom manager that provides common query methods
    """
    
    def active(self):
        """Return only active (not deleted and enabled) records"""
        return self.filter(deleted=False, enable=True)
    
    def inactive(self):
        """Return only inactive records"""
        return self.filter(models.Q(deleted=True) | models.Q(enable=False))
    
    def deleted(self):
        """Return only soft deleted records"""
        return self.filter(deleted=True)
    
    def not_deleted(self):
        """Return only non-deleted records"""
        return self.filter(deleted=False)