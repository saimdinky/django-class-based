"""
Django management command to seed the database with initial data.
Equivalent to NestJS run-seeds functionality.
"""

import logging
from django.core.management.base import BaseCommand
from django.db import transaction
from django.contrib.auth.hashers import make_password

from permissions.models import Permission
from roles.models import Role
from users.models import User


logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Seed the database with initial data (permissions, roles, and users)'

    def add_arguments(self, parser):
        parser.add_argument(
            '--reset',
            action='store_true',
            help='Reset existing data before seeding',
        )

    def handle(self, *args, **options):
        """Main command handler"""
        self.stdout.write(
            self.style.SUCCESS('🌱 Starting database seeding...')
        )

        try:
            with transaction.atomic():
                if options['reset']:
                    self.reset_data()
                
                self.seed_permissions()
                self.seed_roles()
                self.seed_users()
                
            self.stdout.write(
                self.style.SUCCESS('🎉 Database seeding completed successfully!')
            )
            
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'❌ Error during seeding: {str(e)}')
            )
            logger.error(f"Seeding error: {str(e)}", exc_info=True)
            raise

    def reset_data(self):
        """Reset existing data"""
        self.stdout.write('🗑️ Resetting existing data...')
        
        User.objects.all().delete()
        Role.objects.all().delete()
        Permission.objects.all().delete()
        
        self.stdout.write(
            self.style.WARNING('Existing data reset complete')
        )

    def seed_permissions(self):
        """Seed permissions data"""
        self.stdout.write('📋 Seeding permissions...')
        
        permissions_data = [
            {
                'name': 'users.create',
                'url': '/api/users',
                'regex': r'^/api/users/?$',
                'description': 'Create new users'
            },
            {
                'name': 'users.read',
                'url': '/api/users',
                'regex': r'^/api/users(/\d+)?/?$',
                'description': 'Read user information'
            },
            {
                'name': 'users.update',
                'url': '/api/users',
                'regex': r'^/api/users/\d+/?$',
                'description': 'Update user information'
            },
            {
                'name': 'users.delete',
                'url': '/api/users',
                'regex': r'^/api/users/\d+/?$',
                'description': 'Delete users'
            },
            {
                'name': 'roles.create',
                'url': '/api/roles',
                'regex': r'^/api/roles/?$',
                'description': 'Create new roles'
            },
            {
                'name': 'roles.read',
                'url': '/api/roles',
                'regex': r'^/api/roles(/\d+)?/?$',
                'description': 'Read role information'
            },
            {
                'name': 'roles.update',
                'url': '/api/roles',
                'regex': r'^/api/roles/\d+/?$',
                'description': 'Update role information'
            },
            {
                'name': 'roles.delete',
                'url': '/api/roles',
                'regex': r'^/api/roles/\d+/?$',
                'description': 'Delete roles'
            },
            {
                'name': 'permissions.create',
                'url': '/api/permissions',
                'regex': r'^/api/permissions/?$',
                'description': 'Create new permissions'
            },
            {
                'name': 'permissions.read',
                'url': '/api/permissions',
                'regex': r'^/api/permissions(/\d+)?/?$',
                'description': 'Read permission information'
            },
            {
                'name': 'permissions.update',
                'url': '/api/permissions',
                'regex': r'^/api/permissions/\d+/?$',
                'description': 'Update permission information'
            },
            {
                'name': 'permissions.delete',
                'url': '/api/permissions',
                'regex': r'^/api/permissions/\d+/?$',
                'description': 'Delete permissions'
            },
            {
                'name': 'admin.access',
                'url': '/admin',
                'regex': r'^/admin.*$',
                'description': 'Access admin panel'
            }
        ]
        
        created_count = 0
        for perm_data in permissions_data:
            permission, created = Permission.objects.get_or_create(
                name=perm_data['name'],
                defaults={
                    'url': perm_data['url'],
                    'regex': perm_data['regex'],
                    'description': perm_data.get('description', '')
                }
            )
            if created:
                created_count += 1
                self.stdout.write(f'  ✅ Created permission: {permission.name}')
            else:
                self.stdout.write(f'  ⏭️ Permission already exists: {permission.name}')
        
        self.stdout.write(
            self.style.SUCCESS(f'Permissions seeding complete. Created: {created_count}')
        )

    def seed_roles(self):
        """Seed roles data"""
        self.stdout.write('👥 Seeding roles...')
        
        # Define roles and their permissions
        roles_data = [
            {
                'name': 'admin',
                'description': 'Administrator with full access',
                'permissions': [
                    'users.create', 'users.read', 'users.update', 'users.delete',
                    'roles.create', 'roles.read', 'roles.update', 'roles.delete',
                    'permissions.create', 'permissions.read', 'permissions.update', 'permissions.delete',
                    'admin.access'
                ]
            },
            {
                'name': 'user',
                'description': 'Regular user with limited access',
                'permissions': ['users.read']
            },
            {
                'name': 'moderator',
                'description': 'Moderator with user management access',
                'permissions': ['users.read', 'users.update', 'roles.read']
            }
        ]
        
        created_count = 0
        for role_data in roles_data:
            role, created = Role.objects.get_or_create(
                name=role_data['name'],
                defaults={'description': role_data.get('description', '')}
            )
            
            if created:
                created_count += 1
                self.stdout.write(f'  ✅ Created role: {role.name}')
            else:
                self.stdout.write(f'  ⏭️ Role already exists: {role.name}')
            
            # Assign permissions to role
            for perm_name in role_data['permissions']:
                try:
                    permission = Permission.objects.get(name=perm_name)
                    role.add_permission(permission)
                except Permission.DoesNotExist:
                    self.stdout.write(
                        self.style.WARNING(f'  ⚠️ Permission not found: {perm_name}')
                    )
        
        self.stdout.write(
            self.style.SUCCESS(f'Roles seeding complete. Created: {created_count}')
        )

    def seed_users(self):
        """Seed users data"""
        self.stdout.write('👤 Seeding users...')
        
        users_data = [
            {
                'name': 'Admin User',
                'email': 'admin@example.com',
                'password': 'AdminPassword123!',
                'roles': ['admin'],
                'is_staff': True,
                'is_superuser': True
            },
            {
                'name': 'Regular User',
                'email': 'user@example.com',
                'password': 'UserPassword123!',
                'roles': ['user']
            },
            {
                'name': 'Moderator User',
                'email': 'moderator@example.com',
                'password': 'ModeratorPassword123!',
                'roles': ['moderator']
            }
        ]
        
        created_count = 0
        for user_data in users_data:
            user, created = User.objects.get_or_create(
                email=user_data['email'],
                defaults={
                    'name': user_data['name'],
                    'password': make_password(user_data['password']),
                    'is_staff': user_data.get('is_staff', False),
                    'is_superuser': user_data.get('is_superuser', False)
                }
            )
            
            if created:
                created_count += 1
                self.stdout.write(f'  ✅ Created user: {user.email}')
            else:
                self.stdout.write(f'  ⏭️ User already exists: {user.email}')
            
            # Assign roles to user
            for role_name in user_data['roles']:
                try:
                    role = Role.objects.get(name=role_name)
                    user.add_role(role)
                except Role.DoesNotExist:
                    self.stdout.write(
                        self.style.WARNING(f'  ⚠️ Role not found: {role_name}')
                    )
        
        self.stdout.write(
            self.style.SUCCESS(f'Users seeding complete. Created: {created_count}')
        )
        
        # Display login credentials
        self.stdout.write('\n' + '='*50)
        self.stdout.write(self.style.SUCCESS('🔐 Login Credentials:'))
        self.stdout.write('='*50)
        for user_data in users_data:
            self.stdout.write(f"Email: {user_data['email']}")
            self.stdout.write(f"Password: {user_data['password']}")
            self.stdout.write(f"Roles: {', '.join(user_data['roles'])}")
            self.stdout.write('-' * 30)
