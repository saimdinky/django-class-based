# 🚀 Django Class-Based Views

A comprehensive, production-ready Django REST API built with class-based views, JWT authentication, role-based permissions, and modern development practices. This project demonstrates enterprise-grade authentication and authorization functionality using Django's class-based view architecture.

## 📋 Table of Contents

- [🚀 Django Class-Based Views](#-django-class-based-views)
  - [📋 Table of Contents](#-table-of-contents)
  - [✨ Features](#-features)
  - [🛠️ Technology Stack](#️-technology-stack)
  - [📋 Requirements](#-requirements)
  - [🚀 Quick Start](#-quick-start)
  - [🐳 Docker Setup](#-docker-setup)
  - [⚙️ Configuration](#️-configuration)
  - [📚 API Documentation](#-api-documentation)
  - [🔐 Authentication \& Authorization](#-authentication--authorization)
  - [🏗️ Project Structure](#️-project-structure)
  - [🔧 Development](#-development)
  - [🧪 Testing](#-testing)
  - [📊 Monitoring \& Logging](#-monitoring--logging)
  - [🚀 Deployment](#-deployment)
  - [🤝 Contributing](#-contributing)
  - [📄 License](#-license)

## ✨ Features

### 🔐 Authentication & Security

- **JWT Authentication** - Secure token-based authentication with access/refresh tokens
- **Role-Based Access Control (RBAC)** - Flexible permission system with roles and permissions
- **Password Security** - Argon2 password hashing with configurable complexity
- **Rate Limiting** - IP-based rate limiting with Redis backend
- **Security Headers** - Comprehensive security headers (CORS, XSS, CSRF protection)
- **Request Logging** - Detailed request/response logging with performance metrics

### 🏗️ Architecture & Development

- **Class-Based Views** - Modern Django class-based views with proper separation of concerns
- **API Documentation** - Interactive Swagger/OpenAPI documentation
- **Database Agnostic** - Support for MySQL, PostgreSQL, and SQLite
- **Docker Support** - Complete containerization with multi-stage builds
- **Code Quality** - Pre-configured linting, formatting, and type checking
- **Testing Ready** - Comprehensive test setup with pytest and coverage

### 🚀 Production Features

- **Health Checks** - Built-in health check endpoints for monitoring
- **Data Seeding** - Automatic database seeding with initial data
- **Environment Configuration** - Flexible environment-based configuration
- **Logging System** - Structured logging with configurable levels
- **Performance Monitoring** - Request timing and performance metrics
- **Graceful Error Handling** - Comprehensive error handling with proper HTTP status codes

## 🛠️ Technology Stack

| Component            | Technology              | Version         |
| -------------------- | ----------------------- | --------------- |
| **Language**         | Python                  | 3.12+           |
| **Framework**        | Django                  | 5.0.4           |
| **API Framework**    | Django REST Framework   | 3.15.1          |
| **Authentication**   | SimpleJWT               | 5.3.0           |
| **Database**         | MySQL/PostgreSQL/SQLite | 8.0+/13+/Latest |
| **Cache/Session**    | Redis                   | 7.0+            |
| **Documentation**    | drf-spectacular         | 0.27.2          |
| **WSGI Server**      | Gunicorn                | 22.0.0          |
| **Containerization** | Docker & Docker Compose | Latest          |

## 📋 Requirements

### System Requirements

- **Python**: 3.12 or higher
- **Database**: MySQL 8.0+ / PostgreSQL 13+ / SQLite (development)
- **Cache**: Redis 7.0+ (optional, for rate limiting and sessions)
- **Docker**: Latest version (optional, for containerized deployment)

### Python Dependencies

All dependencies are managed in `requirements.txt`:

```bash
# Core Framework
Django==5.0.4
djangorestframework==3.15.1

# Authentication & Security
djangorestframework-simplejwt==5.3.0
argon2-cffi==23.1.0

# Database Drivers
psycopg2-binary==2.9.9  # PostgreSQL
PyMySQL==1.1.0          # MySQL

# Additional features...
```

## 🚀 Quick Start

### 1. Clone Repository

```bash
git clone <repository-url>
cd django-class-based-views
```

### 2. Create Virtual Environment

```bash
python3.12 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Environment Setup

```bash
# Copy environment template
cp env.example .env

# Edit configuration
nano .env
```

### 5. Database Setup

```bash
# Run migrations
python manage.py migrate

# Create superuser
python manage.py createsuperuser

# Seed initial data (optional)
python manage.py seed_data
```

### 6. Start Development Server

```bash
python manage.py runserver 8000
```

🎉 **Your API is now running at `http://localhost:8000`**

## 🐳 Docker Setup

### Quick Start with Docker Compose

```bash
# Start all services (API + MySQL + Redis)
docker-compose up -d

# View logs
docker-compose logs -f api

# Stop services
docker-compose down
```

### Docker Services

| Service   | Port | Description        |
| --------- | ---- | ------------------ |
| **API**   | 8000 | Django application |
| **MySQL** | 3307 | Database server    |
| **Redis** | 6379 | Cache and sessions |

### Production Deployment

```bash
# Build production image
docker-compose -f docker-compose.yml up -d

# Scale API instances
docker-compose up -d --scale api=3
```

## ⚙️ Configuration

### Environment Variables

Create a `.env` file based on `env.example`:

```bash
# Django Configuration
DJANGO_SECRET_KEY=your-secret-key-here
DEBUG=False
ALLOWED_HOSTS=localhost,127.0.0.1,yourdomain.com

# Database Configuration
DB_TYPE=mysql                    # mysql, postgresql, sqlite
DB_HOST=localhost
DB_PORT=3306
DB_USER=root
DB_PASSWORD=your-password
DB_NAME=django_class_based

# JWT Configuration
JWT_SECRET=your-jwt-secret
JWT_TOKEN_EXPIRY=3600           # 1 hour
JWT_REFRESH_EXPIRY=604800       # 7 days

# Rate Limiting
RATE_LIMIT_TTL=60               # Time window in seconds
RATE_LIMIT_LIMIT=100            # Requests per window

# Logging
LOG_LEVEL=INFO                  # DEBUG, INFO, WARNING, ERROR
```

### Database Configuration

#### MySQL

```python
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'django_class_based',
        'USER': 'root',
        'PASSWORD': 'password',
        'HOST': 'localhost',
        'PORT': '3306',
    }
}
```

#### PostgreSQL

```python
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'django_class_based',
        'USER': 'postgres',
        'PASSWORD': 'password',
        'HOST': 'localhost',
        'PORT': '5432',
    }
}
```

## 📚 API Documentation

### Interactive Documentation

- **Swagger UI**: `http://localhost:8000/api/docs/`
- **ReDoc**: `http://localhost:8000/api/redoc/`
- **OpenAPI Schema**: `http://localhost:8000/api/schema/`

### Core Endpoints

#### Authentication Endpoints

```bash
POST   /api/auth/register/         # User registration
POST   /api/auth/login/            # User login
GET    /api/auth/profile/          # Get user profile
POST   /api/auth/change-password/  # Change password
POST   /api/auth/refresh-token/    # Refresh JWT token
```

#### User Management

```bash
GET    /api/users/                 # List users
GET    /api/users/{id}/            # Get user details
GET    /api/users/{id}/roles/      # Get user roles
POST   /api/users/{id}/roles/      # Assign role to user
DELETE /api/users/{id}/roles/      # Remove role from user
```

#### Role & Permission Management

```bash
GET    /api/roles/                 # List roles
GET    /api/roles/{id}/            # Get role details
GET    /api/permissions/           # List permissions
GET    /api/permissions/{id}/      # Get permission details
```

#### System Endpoints

```bash
GET    /health/                    # Health check
GET    /admin/                     # Admin interface
```

### Example API Usage

#### User Registration

```bash
curl -X POST http://localhost:8000/api/auth/register/ \
  -H "Content-Type: application/json" \
  -d '{
    "name": "John Doe",
    "email": "john@example.com",
    "password": "SecurePassword123!",
    "password_confirm": "SecurePassword123!"
  }'
```

#### User Login

```bash
curl -X POST http://localhost:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "password": "SecurePassword123!"
  }'
```

#### Authenticated Request

```bash
curl -X GET http://localhost:8000/api/auth/profile/ \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## 🔐 Authentication & Authorization

### JWT Token Structure

**Access Token Claims:**

```json
{
  "token_type": "access",
  "exp": 1756985938,
  "iat": 1756982338,
  "jti": "c80dcd381dbc434ea081e4228b58a406",
  "user_id": 4,
  "email": "user@example.com",
  "roles": ["admin", "user"],
  "permissions": {
    "users": ["create", "read", "update", "delete"],
    "roles": ["read"]
  }
}
```

### Role-Based Access Control

#### Default Roles

- **Admin**: Full system access
- **User**: Basic user operations
- **Guest**: Read-only access

#### Permission System

```python
# Check user permissions in views
if not user.has_permission('users.create'):
    return Response({'error': 'Insufficient permissions'},
                   status=403)

# Role-based decorators
@require_roles('admin', 'manager')
def admin_only_view(request):
    pass

@require_permissions('users.create')
def create_user_view(request):
    pass
```

## 🏗️ Project Structure

```
djangoBaseSetup/
├── 📁 authentication/          # Authentication app
│   ├── views.py               # Auth endpoints (login, register, etc.)
│   ├── serializers.py         # Request/response serializers
│   ├── urls.py               # Auth URL routing
│   └── models.py             # Auth-related models
├── 📁 users/                  # User management app
│   ├── models.py             # User model with RBAC
│   ├── views.py              # User CRUD operations
│   └── admin.py              # Django admin config
├── 📁 roles/                  # Role management app
│   ├── models.py             # Role and permission models
│   └── views.py              # Role management endpoints
├── 📁 permissions/            # Permission management app
├── 📁 common/                 # Shared utilities
│   ├── middleware.py         # Custom middleware
│   ├── decorators.py         # Custom decorators
│   ├── exceptions.py         # Custom exceptions
│   └── models.py             # Base models
├── 📁 django_auth_starter/    # Project configuration
│   ├── settings.py           # Django settings
│   ├── urls.py              # Main URL routing
│   └── wsgi.py              # WSGI application
├── 📁 tests/                  # Test suite
├── 📁 logs/                   # Application logs
├── 📄 requirements.txt        # Python dependencies
├── 📄 docker-compose.yml      # Docker services
├── 📄 Dockerfile             # Container definition
└── 📄 README.md              # This file
```

## 🔧 Development

### Code Quality Tools

#### Formatting & Linting

```bash
# Format code with Black
black .

# Sort imports with isort
isort .

# Lint with flake8
flake8 .

# Type checking with mypy
mypy .
```

#### Pre-commit Hooks

```bash
# Install pre-commit
pip install pre-commit

# Install hooks
pre-commit install

# Run manually
pre-commit run --all-files
```

### Database Migrations

```bash
# Create migrations
python manage.py makemigrations

# Apply migrations
python manage.py migrate

# Show migration status
python manage.py showmigrations
```

### Custom Management Commands

```bash
# Seed database with initial data
python manage.py seed_data

# Create sample users
python manage.py create_sample_users

# Show URL patterns
python manage.py show_urls
```

## 🧪 Testing

### Test Suite

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=.

# Run specific test file
pytest tests/test_authentication.py

# Run with verbose output
pytest -v
```

### Test Configuration

- **Framework**: pytest + pytest-django
- **Coverage**: pytest-cov
- **Factories**: factory-boy for test data
- **Database**: Separate test database

### Example Test

```python
def test_user_login_success(api_client, user_factory):
    """Test successful user login."""
    user = user_factory(email='test@example.com')

    response = api_client.post('/api/auth/login/', {
        'email': 'test@example.com',
        'password': 'password123'
    })

    assert response.status_code == 200
    assert 'access_token' in response.data
```

## 📊 Monitoring & Logging

### Logging Configuration

**Log Levels:**

- `DEBUG`: Detailed debug information
- `INFO`: General information
- `WARNING`: Warning messages
- `ERROR`: Error messages
- `CRITICAL`: Critical errors

**Log Files:**

- `logs/django.log`: Application logs
- `logs/access.log`: Request access logs
- `logs/error.log`: Error logs

### Health Checks

**Health Check Endpoint:**

```bash
GET /health/

Response:
{
  "status": "healthy",
  "message": "Django Auth Starter API is running",
  "version": "1.0.0",
  "environment": "development",
  "database": "connected",
  "cache": "connected"
}
```

### Performance Monitoring

**Request Metrics:**

- Request duration logging
- Slow query detection
- Rate limiting monitoring
- Error rate tracking

## 🚀 Deployment

### Production Checklist

- [ ] Set `DEBUG = False`
- [ ] Configure secure `SECRET_KEY`
- [ ] Set up proper database (MySQL/PostgreSQL)
- [ ] Configure Redis for caching
- [ ] Set up SSL/HTTPS
- [ ] Configure static file serving
- [ ] Set up monitoring and logging
- [ ] Configure backup strategy

### Docker Production Deployment

```bash
# Build production image
docker build --target production -t django-auth-api .

# Run with docker-compose
docker-compose -f docker-compose.prod.yml up -d

# Scale application
docker-compose up -d --scale api=3
```

### Environment-Specific Settings

**Development:**

```bash
DEBUG=True
DB_TYPE=sqlite
LOG_LEVEL=DEBUG
```

**Staging:**

```bash
DEBUG=False
DB_TYPE=mysql
LOG_LEVEL=INFO
ALLOWED_HOSTS=staging.yourdomain.com
```

**Production:**

```bash
DEBUG=False
DB_TYPE=mysql
LOG_LEVEL=WARNING
ALLOWED_HOSTS=yourdomain.com
SECURE_SSL_REDIRECT=True
```

## 🤝 Contributing

### Development Setup

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

### Code Standards

- Follow PEP 8 style guidelines
- Add docstrings to all functions and classes
- Write comprehensive tests
- Update documentation for new features

### Commit Messages

```bash
feat: add user profile update endpoint
fix: resolve JWT token refresh issue
docs: update API documentation
test: add authentication test cases
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🆘 Support & Documentation

- **Issues**: [GitHub Issues](https://github.com/your-repo/issues)
- **Documentation**: [API Docs](http://localhost:8000/api/docs/)

---

**Built with ❤️ using Django and modern Python practices**

_This project serves as a comprehensive foundation for building secure, scalable Django REST APIs with enterprise-grade authentication and authorization._
