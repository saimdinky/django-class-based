-- Initial MySQL database setup
-- Database initialization for Django Class-Based Views project

-- Create database if it doesn't exist
CREATE DATABASE IF NOT EXISTS django;

-- Use the database
USE django;

-- Grant privileges to root user
GRANT ALL PRIVILEGES ON django.* TO 'root'@'%';
FLUSH PRIVILEGES;

-- Set character set and collation
ALTER DATABASE django CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
