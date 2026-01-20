# Authentication Skill - Key Features

## Overview
Enterprise-grade authentication system for FastAPI + React with comprehensive security features, user profile management, automatic dependency management, and full automation.

## Core Authentication Features
- **JWT Authentication**: Access + refresh tokens with automatic rotation
- **User Registration & Login**: With strong validation and security
- **Password Security**: Bcrypt hashing with 12+ character requirements, special characters, no common passwords
- **Session Management**: With device tracking and security monitoring

## User Profile Management
- **Complete Profile System**: Username, phone number, first name, last name, bio, avatar URL
- **Profile Editing**: Real-time profile updates with validation
- **Extended Registration**: Support for profile fields during sign-up (username, names, phone)
- **Profile Privacy**: Configurable visibility settings

## Automatic Dependency Management
- **Backend Dependencies**: Automatically installs all required packages (passlib, python-jose, fastapi-mail, pyotp, httpx, qrcode, pillow, bcrypt, pydantic-settings, python-multipart, sqlalchemy, psycopg2-binary, alembic, python-jose[cryptography], passlib[bcrypt])
- **Frontend Dependencies**: Automatically installs all required packages (axios, react-router-dom, zustand, react-hook-form, zod, @types/react, @types/node, @types/react-dom)
- **Zero-Install Setup**: No manual dependency installation required
- **Version Compatibility**: Ensures all dependencies work together

## Security & Validation
- **Account Protection**: Lockout after 5 failed attempts (15-minute window)
- **Password History**: Prevents reuse of last 5 passwords
- **Email Validation**: Case-insensitive uniqueness checking
- **Username & Phone Validation**: Unique field validation with error handling
- **SQL Injection & XSS Protection**: Input sanitization and validation

## Advanced Features
- **OAuth Integration**: Google and GitHub support
- **2FA with TOTP**: Google Authenticator compatible with backup codes
- **Email Verification**: Secure token-based verification system
- **Password Reset**: Secure flow with expiration handling

## Security Monitoring
- **Audit Logging**: Comprehensive compliance logging
- **Login Attempt Tracking**: With IP and user agent logging
- **Brute Force Protection**: Configurable rate limiting
- **Security Event Monitoring**: Centralized logging and alerting

## Production Ready
- **Comprehensive Testing**: Full test suite included
- **Role-Based Access Control**: Permission checking decorators
- **Scalable Architecture**: Designed for enterprise deployment
- **Zero-Touch Setup**: One-command installation and configuration
- **Complete User Experience**: Full login, logout, and profile management flow