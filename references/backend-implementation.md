# Backend Implementation Guide

Complete backend implementation for JWT authentication in FastAPI.

## Configuration

### Settings File (`backend/src/config/settings.py`)

```python
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # JWT Configuration
    secret_key: str  # Load from environment variable SECRET_KEY
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7

    # OAuth Configuration
    google_client_id: str = ""
    google_client_secret: str = ""
    github_client_id: str = ""
    github_client_secret: str = ""

    # Database
    database_url: str

    class Config:
        env_file = ".env"
        case_sensitive = False

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Validate SECRET_KEY is set
        if not self.secret_key or self.secret_key == "your-secret-key-here":
            raise ValueError("SECRET_KEY must be set in environment variables")

settings = Settings()
```

**Environment Variables** (`.env`):
```
SECRET_KEY=your-secure-random-secret-key-here
DATABASE_URL=postgresql://user:password@host:port/database
```

Generate SECRET_KEY with: `openssl rand -hex 32`

## User Model

### Database Model (`backend/src/database/models.py`)

```python
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Index, ForeignKey, Table
from sqlalchemy.orm import relationship, declarative_base
from datetime import datetime

Base = declarative_base()

# Association table for User-Role (Many-to-Many)
user_roles = Table(
    "user_roles",
    Base.metadata,
    Column("user_id", Integer, ForeignKey("users.id"), primary_key=True),
    Column("role_id", Integer, ForeignKey("roles.id"), primary_key=True),
)

# Association table for Role-Permission (Many-to-Many)
role_permissions = Table(
    "role_permissions",
    Base.metadata,
    Column("role_id", Integer, ForeignKey("roles.id"), primary_key=True),
    Column("permission_id", Integer, ForeignKey("permissions.id"), primary_key=True),
)

class Permission(Base):
    __tablename__ = "permissions"
    id = Column(Integer, primary_key=True)
    name = Column(String(50), unique=True, nullable=False)  # e.g., "user:write"
    description = Column(String(255))

class Role(Base):
    __tablename__ = "roles"
    id = Column(Integer, primary_key=True)
    name = Column(String(50), unique=True, nullable=False)  # e.g., "admin"
    permissions = relationship("Permission", secondary=role_permissions, backref="roles")

class User(Base):
    """User model for authentication."""
    __tablename__ = "users"

    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)

    # Email (unique, indexed)
    email = Column(String(255), unique=True, nullable=False, index=True)

    # Username (unique, indexed)
    username = Column(String(50), unique=True, nullable=True, index=True)

    # Phone number
    phone_number = Column(String(20), unique=True, nullable=True, index=True)

    # Profile information
    first_name = Column(String(100), nullable=True)
    last_name = Column(String(100), nullable=True)
    bio = Column(String(500), nullable=True)
    avatar_url = Column(String(500), nullable=True)

    # Hashed password
    hashed_password = Column(String(255), nullable=True) # Nullable for OAuth-only users

    # Account status
    is_active = Column(Boolean, default=True, nullable=False)
    is_verified = Column(Boolean, default=False, nullable=False)

    # 2FA status
    two_factor_enabled = Column(Boolean, default=False)
    two_factor_secret = Column(String(32), nullable=True)

    # Relationships
    roles = relationship("Role", secondary=user_roles, backref="users")
    refresh_tokens = relationship("RefreshToken", back_populates="user", cascade="all, delete-orphan")

    # Timestamps
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=True)
    last_login_at = Column(DateTime, nullable=True)

    # Indexes
    __table_args__ = (
        Index('idx_user_email', 'email'),
        Index('idx_user_username', 'username'),
        Index('idx_user_phone', 'phone_number'),
    )

class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    id = Column(Integer, primary_key=True)
    token = Column(String(255), unique=True, nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    is_revoked = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="refresh_tokens")

class Session(Base):
    """User session tracking for multi-device support."""
    __tablename__ = "sessions"
    id = Column(Integer, primary_key=True)
    session_id = Column(String(255), unique=True, nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    device_info = Column(String(500))  # Browser, OS, device type
    ip_address = Column(String(45))  # IPv4 or IPv6
    location = Column(String(100))  # Country/City
    last_active = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", foreign_keys=[user_id])

class LoginAttempt(Base):
    """Track login attempts for brute force protection."""
    __tablename__ = "login_attempts"
    id = Column(Integer, primary_key=True)
    email = Column(String(255), nullable=False, index=True)
    ip_address = Column(String(45))
    user_agent = Column(String(500))
    success = Column(Boolean, default=False)
    failure_reason = Column(String(100))
    created_at = Column(DateTime, default=datetime.utcnow)

class PasswordHistory(Base):
    """Store password history to prevent reuse."""
    __tablename__ = "password_history"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", foreign_keys=[user_id])

class AuditLog(Base):
    """Security audit logging for compliance."""
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    action = Column(String(100), nullable=False)  # e.g., "login", "password_change"
    resource = Column(String(100))  # e.g., "/auth/login", "User:123"
    details = Column(Text)  # JSON details of the action
    ip_address = Column(String(45))
    user_agent = Column(String(500))
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", foreign_keys=[user_id])
```

### Database Initialization

```python
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from .models import Base

engine = create_engine(settings.database_url)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    """Initialize database tables."""
    Base.metadata.create_all(bind=engine)

def get_db():
    """Dependency for database sessions."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
```

## Auth Utilities

### Password & JWT Utilities (`backend/src/api/auth_utils.py`)

```python
import secrets
import logging
import re
from datetime import datetime, timedelta
from typing import Optional, List, Callable

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from sqlalchemy import func
from ..config.settings import settings
from ..database import get_db
from ..database.models import User, RefreshToken, Role, Permission, PasswordHistory

# Decorator for checking permissions
def has_permission(permission_name: str):
    def decorator(func: Callable):
        async def wrapper(*args, current_user: User = Depends(get_current_user), **kwargs):
            user_permissions = []
            for role in current_user.roles:
                user_permissions.extend([p.name for p in role.permissions])

            if permission_name not in user_permissions and "admin" not in [r.name for r in current_user.roles]:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Missing permission: {permission_name}"
                )
            return await func(*args, current_user=current_user, **kwargs)
        return wrapper
    return decorator

def create_refresh_token(db: Session, user_id: int) -> str:
    """Create and store a secure refresh token."""
    token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(days=settings.refresh_token_expire_days)

    db_token = RefreshToken(
        token=token,
        user_id=user_id,
        expires_at=expires_at
    )
    db.add(db_token)
    db.commit()
    return token

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token."""
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=settings.access_token_expire_minutes))
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)

def verify_token(token: str) -> dict:
    """Verify and decode JWT token."""
    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.algorithm]
        )
        logger.info(f"Token verified successfully. Payload: {payload}")
        return payload
    except JWTError as e:
        logger.error(f"Token verification failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> User:
    """Get current authenticated user from JWT token."""
    payload = verify_token(token)
    user_id: str = payload.get("sub")

    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials"
        )

    user = db.query(User).filter(User.id == int(user_id)).first()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user"
        )

    return user

def authenticate_user(db: Session, email: str, password: str) -> Optional[User]:
    """Authenticate user with email and password."""
    user = db.query(User).filter(User.email == email).first()

    if not user:
        return None

    if not verify_password(password, user.hashed_password):
        return None

    return user

def create_user(db: Session, email: str, password: str) -> User:
    """Create new user with hashed password."""
    hashed_password = hash_password(password)

    user = User(
        email=email,
        hashed_password=hashed_password,
        is_active=True,
        created_at=datetime.utcnow()
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    return user

def get_user_by_email(db: Session, email: str) -> Optional[User]:
    """Get user by email."""
    # Case-insensitive email lookup
    return db.query(User).filter(func.lower(User.email) == func.lower(email)).first()


def validate_email_uniqueness(db: Session, email: str, exclude_user_id: Optional[int] = None) -> bool:
    """Validate that email is unique, excluding current user if updating."""
    query = db.query(User).filter(func.lower(User.email) == func.lower(email))
    if exclude_user_id:
        query = query.filter(User.id != exclude_user_id)

    return query.first() is None


def validate_strong_password(password: str) -> bool:
    """
    Validate password meets strong requirements:
    - At least 12 characters
    - Contains uppercase, lowercase, digit, and special character
    - Not in common password lists
    """
    # Length check
    if len(password) < 12:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 12 characters long"
        )

    # Complexity check
    if not re.search(r"[A-Z]", password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must contain at least one uppercase letter"
        )

    if not re.search(r"[a-z]", password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must contain at least one lowercase letter"
        )

    if not re.search(r"\d", password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must contain at least one digit"
        )

    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must contain at least one special character (!@#$%^&*(),.?\":{}|<>)"
        )

    # Common password check (basic implementation)
    common_passwords = ['password', '12345678', 'qwerty', 'abc123', 'password123']
    if password.lower() in common_passwords:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password is too common, please choose a stronger password"
        )

    return True


def check_password_history(db: Session, user_id: int, password: str) -> bool:
    """Check if the new password matches any of the last 5 passwords."""
    # Get the last 5 passwords from history
    password_histories = (
        db.query(PasswordHistory)
        .filter(PasswordHistory.user_id == user_id)
        .order_by(PasswordHistory.created_at.desc())
        .limit(5)
        .all()
    )

    for hist in password_histories:
        if verify_password(password, hist.password_hash):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="New password cannot be the same as any of your last 5 passwords"
            )

    return True


def create_user(db: Session, email: str, password: str) -> User:
    """Create new user with strong password validation and email uniqueness."""
    # Validate email uniqueness (case-insensitive)
    if not validate_email_uniqueness(db, email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email is already registered"
        )

    # Validate strong password requirements
    validate_strong_password(password)

    # Hash the password
    hashed_password = hash_password(password)

    # Create user
    user = User(
        email=email,
        hashed_password=hashed_password,
        is_active=True,
        is_verified=False,  # User needs to verify email
        created_at=datetime.utcnow()
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    # Add to password history
    password_history = PasswordHistory(
        user_id=user.id,
        password_hash=hashed_password
    )
    db.add(password_history)
    db.commit()

    return user


def update_user_password(db: Session, user: User, new_password: str) -> User:
    """Update user password with validation."""
    # Validate strong password requirements
    validate_strong_password(new_password)

    # Check password history
    check_password_history(db, user.id, new_password)

    # Hash new password
    hashed_new_password = hash_password(new_password)

    # Update password
    user.hashed_password = hashed_new_password
    db.commit()
    db.refresh(user)

    # Add to password history
    password_history = PasswordHistory(
        user_id=user.id,
        password_hash=hashed_new_password
    )
    db.add(password_history)
    db.commit()

    return user


def get_user_by_username(db: Session, username: str) -> Optional[User]:
    """Get user by username."""
    return db.query(User).filter(func.lower(User.username) == func.lower(username)).first()


def get_user_by_phone_number(db: Session, phone_number: str) -> Optional[User]:
    """Get user by phone number."""
    return db.query(User).filter(User.phone_number == phone_number).first()


def create_user_with_profile(db: Session, email: str, password: str, request: RegisterRequest) -> User:
    """Create new user with profile information."""
    # Validate email uniqueness (case-insensitive)
    if not validate_email_uniqueness(db, email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email is already registered"
        )

    # Validate strong password requirements
    validate_strong_password(password)

    # Hash the password
    hashed_password = hash_password(password)

    # Create user with profile info
    user = User(
        email=email,
        username=request.username,
        phone_number=request.phone_number,
        first_name=request.first_name,
        last_name=request.last_name,
        bio=request.bio,
        avatar_url=request.avatar_url,
        hashed_password=hashed_password,
        is_active=True,
        is_verified=False,  # User needs to verify email
        created_at=datetime.utcnow()
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    # Add to password history
    password_history = PasswordHistory(
        user_id=user.id,
        password_hash=hashed_password
    )
    db.add(password_history)
    db.commit()

    return user


def generate_verification_token(user_id: int) -> str:
    """Generate a secure verification token for email verification."""
    import secrets
    token = secrets.token_urlsafe(32)

    # Create a JWT token with expiration
    from datetime import datetime, timedelta
    from jose import jwt

    data = {
        "sub": str(user_id),
        "type": "email_verification",
        "exp": datetime.utcnow() + timedelta(hours=24)  # Token expires in 24 hours
    }

    verification_token = jwt.encode(data, settings.secret_key, algorithm=settings.algorithm)
    return verification_token


def verify_email_token(token: str) -> Optional[int]:
    """Verify the email verification token and return user ID."""
    from jose import JWTError, jwt
    from datetime import datetime

    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])

        # Verify token type
        token_type = payload.get("type")
        if token_type != "email_verification":
            return None

        user_id: str = payload.get("sub")
        if user_id is None:
            return None

        return int(user_id)
    except JWTError:
        return None


def send_verification_email(db: Session, user: User, base_url: str = "http://localhost:3000"):
    """Send email verification email to user."""
    # This would integrate with an email service like SendGrid, SMTP, etc.
    # For now, we'll just return the verification link
    verification_token = generate_verification_token(user.id)
    verification_link = f"{base_url}/verify-email?token={verification_token}"

    # In a real implementation, you would send an email using an email service
    # Example with SMTP:
    # from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
    # ... send email with verification link ...

    logger.info(f"Verification email sent to {user.email} with link: {verification_link}")
    return verification_link


def generate_password_reset_token(user_id: int) -> str:
    """Generate a secure password reset token."""
    # Create a JWT token with expiration
    from datetime import datetime, timedelta
    from jose import jwt

    data = {
        "sub": str(user_id),
        "type": "password_reset",
        "exp": datetime.utcnow() + timedelta(hours=1)  # Token expires in 1 hour
    }

    reset_token = jwt.encode(data, settings.secret_key, algorithm=settings.algorithm)
    return reset_token


def verify_password_reset_token(token: str) -> Optional[int]:
    """Verify the password reset token and return user ID."""
    from jose import JWTError, jwt

    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])

        # Verify token type
        token_type = payload.get("type")
        if token_type != "password_reset":
            return None

        user_id: str = payload.get("sub")
        if user_id is None:
            return None

        return int(user_id)
    except JWTError:
        return None


def send_password_reset_email(db: Session, user: User, base_url: str = "http://localhost:3000"):
    """Send password reset email to user."""
    # Generate password reset token
    reset_token = generate_password_reset_token(user.id)
    reset_link = f"{base_url}/reset-password?token={reset_token}"

    # In a real implementation, you would send an email using an email service
    # Example with SMTP:
    # from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
    # ... send email with reset link ...

    logger.info(f"Password reset email sent to {user.email} with link: {reset_link}")
    return reset_link


# OAuth2 Utilities
import httpx
from urllib.parse import urlencode
from fastapi import Request


def get_google_user_info(access_token: str) -> dict:
    """Get user info from Google using access token."""
    headers = {"Authorization": f"Bearer {access_token}"}

    with httpx.Client() as client:
        response = client.get("https://www.googleapis.com/oauth2/v2/userinfo", headers=headers)

    if response.status_code != 200:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to fetch user info from Google"
        )

    return response.json()


def get_github_user_info(access_token: str) -> dict:
    """Get user info from GitHub using access token."""
    headers = {"Authorization": f"token {access_token}"}

    with httpx.Client() as client:
        response = client.get("https://api.github.com/user", headers=headers)

    if response.status_code != 200:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to fetch user info from GitHub"
        )

    return response.json()


def get_or_create_oauth_user(db: Session, provider: str, provider_id: str, email: str, name: str) -> User:
    """Get existing user by OAuth provider ID or create new user."""
    # First, try to find user by provider ID
    user = db.query(User).filter(
        User.email == email
    ).first()

    if user:
        # Update provider-specific info if needed
        # In a real implementation, you might want to link multiple OAuth providers to one account
        return user

    # Create new user if not found
    # Generate a temporary password since OAuth users don't have passwords initially
    temp_password = secrets.token_urlsafe(32)
    hashed_password = hash_password(temp_password)

    user = User(
        email=email,
        hashed_password=hashed_password,  # Still store a password hash for consistency
        is_active=True,
        is_verified=True,  # OAuth emails are typically verified by the provider
        created_at=datetime.utcnow()
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    # Add to password history
    password_history = PasswordHistory(
        user_id=user.id,
        password_hash=hashed_password
    )
    db.add(password_history)
    db.commit()

    return user


# 2FA (Two-Factor Authentication) Utilities
def generate_totp_secret() -> str:
    """Generate a new TOTP secret for 2FA."""
    import pyotp
    return pyotp.random_base32()


def get_totp_uri(email: str, secret: str) -> str:
    """Generate a TOTP URI for QR code generation."""
    import pyotp
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(
        name=email,
        issuer_name="Your App Name",
        initial_count=1
    )


def verify_totp_token(secret: str, token: str) -> bool:
    """Verify a TOTP token."""
    import pyotp
    totp = pyotp.TOTP(secret)
    # Allow some time drift (typically 30 seconds window)
    return totp.verify(token, valid_window=1)


def generate_backup_codes(count: int = 10) -> List[str]:
    """Generate backup codes for 2FA recovery."""
    import secrets
    return [secrets.token_urlsafe(16)[:8].upper() for _ in range(count)]


# Security Monitoring Utilities
def log_login_attempt(db: Session, email: str, ip_address: str, user_agent: str, success: bool, failure_reason: Optional[str] = None):
    """Log a login attempt for security monitoring."""
    from sqlalchemy import text

    login_attempt = LoginAttempt(
        email=email,
        ip_address=ip_address,
        user_agent=user_agent,
        success=success,
        failure_reason=failure_reason
    )

    db.add(login_attempt)
    db.commit()


def is_account_locked(db: Session, email: str, max_attempts: int = 5, time_window: int = 900) -> bool:
    """Check if account is locked due to too many failed attempts."""
    from datetime import datetime, timedelta

    cutoff_time = datetime.utcnow() - timedelta(seconds=time_window)

    failed_attempts = db.query(LoginAttempt).filter(
        LoginAttempt.email == email,
        LoginAttempt.success == False,
        LoginAttempt.created_at > cutoff_time
    ).count()

    return failed_attempts >= max_attempts


def log_audit_event(db: Session, user_id: Optional[int], action: str, resource: Optional[str] = None,
                   details: Optional[dict] = None, ip_address: Optional[str] = None,
                   user_agent: Optional[str] = None):
    """Log an audit event for compliance and security."""
    import json

    audit_log = AuditLog(
        user_id=user_id,
        action=action,
        resource=resource,
        details=json.dumps(details) if details else None,
        ip_address=ip_address,
        user_agent=user_agent
    )

    db.add(audit_log)
    db.commit()


def get_recent_failed_attempts(db: Session, email: str, time_window: int = 900) -> int:
    """Get count of failed attempts in the specified time window."""
    from datetime import datetime, timedelta

    cutoff_time = datetime.utcnow() - timedelta(seconds=time_window)

    failed_attempts = db.query(LoginAttempt).filter(
        LoginAttempt.email == email,
        LoginAttempt.success == False,
        LoginAttempt.created_at > cutoff_time
    ).count()

    return failed_attempts
```

## Endpoints

### Auth Endpoints (`backend/src/api/auth_endpoints.py`)

```python
import logging
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from .auth_utils import (
    authenticate_user,
    create_access_token,
    get_current_user,
    create_user,
    get_user_by_email
)
from ..database import get_db
from ..database.models import User
from ..config.settings import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["authentication"])

# Request/Response Models
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    username: Optional[str] = None
    phone_number: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    bio: Optional[str] = None
    avatar_url: Optional[str] = None

class AuthResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user_id: int
    email: str
    roles: List[str]
    expires_in: int  # seconds

class UserResponse(BaseModel):
    id: int
    email: EmailStr
    username: Optional[str] = None
    phone_number: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    bio: Optional[str] = None
    avatar_url: Optional[str] = None
    is_active: bool
    is_verified: bool
    created_at: str
    updated_at: Optional[str] = None

@router.post("/register", response_model=AuthResponse, status_code=status.HTTP_201_CREATED)
def register(request: RegisterRequest, db: Session = Depends(get_db)) -> AuthResponse:
    """Register a new user account."""
    # Check if user already exists
    existing_user = get_user_by_email(db, request.email)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )

    # Check if username is already taken
    if request.username:
        existing_username_user = get_user_by_username(db, request.username)
        if existing_username_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username is already taken"
            )

    # Check if phone number is already taken
    if request.phone_number:
        existing_phone_user = get_user_by_phone_number(db, request.phone_number)
        if existing_phone_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Phone number is already taken"
            )

    # Create new user with profile info
    user = create_user_with_profile(db, request.email, request.password, request)

    # Create access and refresh tokens
    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
    access_token = create_access_token(
        data={"sub": str(user.id)},
        expires_delta=access_token_expires
    )
    refresh_token = create_refresh_token(db, user.id)

    logger.info(f"New user registered: {user.email}")

    return AuthResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        user_id=user.id,
        email=user.email,
        roles=[role.name for role in user.roles],
        expires_in=settings.access_token_expire_minutes * 60
    )

@router.post("/login", response_model=AuthResponse)
def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
) -> AuthResponse:
    """Authenticate user and return JWT token."""
    # Get IP address and user agent for security logging
    ip_address = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")

    # Check if account is locked due to too many failed attempts
    if is_account_locked(db, form_data.username):
        log_login_attempt(db, form_data.username, ip_address, user_agent, False, "Account locked due to too many failed attempts")

        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail="Account temporarily locked due to too many failed login attempts. Please try again later.",
        )

    # Authenticate user
    user = authenticate_user(db, form_data.username, form_data.password)

    if not user:
        # Log failed attempt
        log_login_attempt(db, form_data.username, ip_address, user_agent, False, "Invalid credentials")

        # Log audit event
        log_audit_event(db, None, "login_failed", "auth.login",
                       {"reason": "invalid_credentials", "email": form_data.username},
                       ip_address, user_agent)

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Log successful attempt
    log_login_attempt(db, form_data.username, ip_address, user_agent, True)

    # Log audit event
    log_audit_event(db, user.id, "login_success", "auth.login",
                   {"ip_address": ip_address, "user_agent": user_agent},
                   ip_address, user_agent)

    # Update last login time
    user.last_login_at = datetime.utcnow()
    db.commit()

    # Create access and refresh tokens
    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
    access_token = create_access_token(
        data={"sub": str(user.id)},
        expires_delta=access_token_expires
    )
    refresh_token = create_refresh_token(db, user.id)

    logger.info(f"User logged in: {user.email}")

    return AuthResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        user_id=user.id,
        email=user.email,
        roles=[role.name for role in user.roles],
        expires_in=settings.access_token_expire_minutes * 60
    )

@router.post("/logout")
def logout() -> dict:
    """Logout endpoint (handled client-side)."""
    return {"message": "Successfully logged out"}

@router.get("/me", response_model=UserResponse)
def get_user_info(current_user: User = Depends(get_current_user)) -> UserResponse:
    """Get current authenticated user information."""
    return UserResponse(
        id=current_user.id,
        email=current_user.email,
        username=current_user.username,
        phone_number=current_user.phone_number,
        first_name=current_user.first_name,
        last_name=current_user.last_name,
        bio=current_user.bio,
        avatar_url=current_user.avatar_url,
        is_active=current_user.is_active,
        is_verified=current_user.is_verified,
        created_at=current_user.created_at.isoformat(),
        updated_at=current_user.updated_at.isoformat() if current_user.updated_at else None
    )


class VerifyEmailRequest(BaseModel):
    token: str


@router.post("/verify-email", status_code=status.HTTP_200_OK)
def verify_email(request: VerifyEmailRequest, db: Session = Depends(get_db)) -> dict:
    """Verify user email using the token sent to their email."""
    # Verify the token
    user_id = verify_email_token(request.token)

    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired verification token"
        )

    # Get the user
    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Verify the email
    if user.is_verified:
        return {"message": "Email is already verified"}

    user.is_verified = True
    db.commit()

    logger.info(f"Email verified for user: {user.email}")
    return {"message": "Email successfully verified"}


@router.post("/resend-verification", status_code=status.HTTP_200_OK)
def resend_verification_email(
    request: RegisterRequest,  # Using the same request model as registration
    db: Session = Depends(get_db)
) -> dict:
    """Resend email verification to user."""
    user = get_user_by_email(db, request.email)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    if user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email is already verified"
        )

    # Send verification email
    send_verification_email(db, user)

    return {"message": "Verification email resent successfully"}


class UpdateProfileRequest(BaseModel):
    username: Optional[str] = None
    phone_number: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    bio: Optional[str] = None
    avatar_url: Optional[str] = None


@router.put("/profile", response_model=UserResponse)
def update_profile(
    request: UpdateProfileRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> UserResponse:
    """Update user profile information."""
    # Update only provided fields
    if request.username is not None:
        # Check if username is already taken by another user
        existing_user = db.query(User).filter(
            User.username == request.username,
            User.id != current_user.id
        ).first()
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username is already taken"
            )
        current_user.username = request.username

    if request.phone_number is not None:
        # Check if phone number is already taken by another user
        existing_user = db.query(User).filter(
            User.phone_number == request.phone_number,
            User.id != current_user.id
        ).first()
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Phone number is already taken"
            )
        current_user.phone_number = request.phone_number

    if request.first_name is not None:
        current_user.first_name = request.first_name
    if request.last_name is not None:
        current_user.last_name = request.last_name
    if request.bio is not None:
        current_user.bio = request.bio
    if request.avatar_url is not None:
        current_user.avatar_url = request.avatar_url

    # Update the timestamp
    current_user.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(current_user)

    # Log the profile update
    log_audit_event(db, current_user.id, "profile_updated", "auth.profile",
                   {"updated_fields": [k for k, v in request.model_dump().items() if v is not None]},
                   None, None)

    # Return updated user info
    return UserResponse(
        id=current_user.id,
        email=current_user.email,
        username=current_user.username,
        phone_number=current_user.phone_number,
        first_name=current_user.first_name,
        last_name=current_user.last_name,
        bio=current_user.bio,
        avatar_url=current_user.avatar_url,
        is_active=current_user.is_active,
        is_verified=current_user.is_verified,
        created_at=current_user.created_at.isoformat(),
        updated_at=current_user.updated_at.isoformat() if current_user.updated_at else None
    )


@router.get("/profile/{user_id}", response_model=UserResponse)
def get_user_profile(
    user_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> UserResponse:
    """Get another user's profile information."""
    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    return UserResponse(
        id=user.id,
        email=user.email,
        username=user.username,
        phone_number=user.phone_number,
        first_name=user.first_name,
        last_name=user.last_name,
        bio=user.bio,
        avatar_url=user.avatar_url,
        is_active=user.is_active,
        is_verified=user.is_verified,
        created_at=user.created_at.isoformat(),
        updated_at=user.updated_at.isoformat() if user.updated_at else None
    )


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


@router.post("/forgot-password", status_code=status.HTTP_200_OK)
def forgot_password(request: ForgotPasswordRequest, db: Session = Depends(get_db)) -> dict:
    """Initiate password reset process by sending reset email."""
    user = get_user_by_email(db, request.email)

    if not user:
        # Don't reveal if email exists to prevent enumeration attacks
        return {"message": "If the email exists, a password reset link has been sent"}

    # Send password reset email
    send_password_reset_email(db, user)

    logger.info(f"Password reset initiated for email: {request.email}")
    return {"message": "If the email exists, a password reset link has been sent"}


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str


@router.post("/reset-password", status_code=status.HTTP_200_OK)
def reset_password(request: ResetPasswordRequest, db: Session = Depends(get_db)) -> dict:
    """Reset user password using the reset token."""
    # Verify the token
    user_id = verify_password_reset_token(request.token)

    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired password reset token"
        )

    # Get the user
    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Validate new password
    validate_strong_password(request.new_password)

    # Update password with validation
    update_user_password(db, user, request.new_password)

    logger.info(f"Password reset successful for user: {user.email}")
    return {"message": "Password has been reset successfully"}


# OAuth Endpoints
from fastapi import Request
from urllib.parse import urlencode


@router.get("/oauth/google")
def google_login(request: Request):
    """Initiate Google OAuth login."""
    google_auth_url = (
        f"https://accounts.google.com/o/oauth2/auth?"
        f"client_id={settings.google_client_id}&"
        f"redirect_uri={request.base_url}auth/oauth/callback/google&"
        f"response_type=code&"
        f"scope=openid email profile"
    )
    return {"auth_url": google_auth_url}


@router.get("/oauth/github")
def github_login(request: Request):
    """Initiate GitHub OAuth login."""
    github_auth_url = (
        f"https://github.com/login/oauth/authorize?"
        f"client_id={settings.github_client_id}&"
        f"redirect_uri={request.base_url}auth/oauth/callback/github&"
        f"scope=user:email"
    )
    return {"auth_url": github_auth_url}


class OAuthCallbackRequest(BaseModel):
    code: str
    provider: str  # "google" or "github"


@router.get("/oauth/callback/{provider}")
async def oauth_callback(provider: str, code: str, db: Session = Depends(get_db)):
    """Handle OAuth callback and return JWT token."""
    if provider not in ["google", "github"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported OAuth provider"
        )

    # Exchange code for access token
    if provider == "google":
        token_url = "https://oauth2.googleapis.com/token"
        data = {
            "code": code,
            "client_id": settings.google_client_id,
            "client_secret": settings.google_client_secret,
            "redirect_uri": f"{settings.frontend_url}/auth/oauth/callback/google" if hasattr(settings, 'frontend_url') else f"http://localhost:3000/auth/oauth/callback/google",
            "grant_type": "authorization_code"
        }
    elif provider == "github":
        token_url = "https://github.com/login/oauth/access_token"
        data = {
            "code": code,
            "client_id": settings.github_client_id,
            "client_secret": settings.github_client_secret,
            "redirect_uri": f"{settings.frontend_url}/auth/oauth/callback/github" if hasattr(settings, 'frontend_url') else f"http://localhost:3000/auth/oauth/callback/github"
        }

    # Request access token
    async with httpx.AsyncClient() as client:
        response = await client.post(token_url, data=data)

        if response.status_code != 200:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to exchange code for token from {provider}"
            )

        token_data = response.json()
        access_token = token_data.get("access_token") or token_data.get("access_token")

    if not access_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to get access token from provider"
        )

    # Get user info from provider
    if provider == "google":
        user_info = get_google_user_info(access_token)
        provider_id = user_info.get("id")
        email = user_info.get("email")
        name = user_info.get("name", "")
    elif provider == "github":
        user_info = get_github_user_info(access_token)
        provider_id = str(user_info.get("id"))
        email = user_info.get("email") or user_info.get("login") + "@users.noreply.github.com"  # Fallback if email not public
        name = user_info.get("name", user_info.get("login"))

    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unable to retrieve email from OAuth provider"
        )

    # Get or create user
    user = get_or_create_oauth_user(db, provider, provider_id, email, name)

    # Create JWT tokens
    access_token = create_access_token(data={"sub": str(user.id)})
    refresh_token = create_refresh_token(db, user.id)

    return AuthResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        user_id=user.id,
        email=user.email,
        roles=[role.name for role in user.roles],
        expires_in=settings.access_token_expire_minutes * 60
    )


# 2FA Endpoints
class Enable2FARequest(BaseModel):
    password: str


class Verify2FATokenRequest(BaseModel):
    token: str


class Disable2FARequest(BaseModel):
    password: str


@router.post("/2fa/enable", status_code=status.HTTP_200_OK)
def enable_2fa(
    request: Enable2FARequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> dict:
    """Enable 2FA for the current user."""
    # Verify user password for security
    if not verify_password(request.password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid password"
        )

    # Generate a new TOTP secret
    secret = generate_totp_secret()

    # Generate backup codes
    backup_codes = generate_backup_codes()

    # Store the secret in the user record
    current_user.two_factor_secret = secret
    current_user.two_factor_enabled = True
    db.commit()

    # Generate provisioning URI for QR code
    uri = get_totp_uri(current_user.email, secret)

    return {
        "secret": secret,
        "qr_code_uri": uri,
        "backup_codes": backup_codes
    }


@router.post("/2fa/verify", status_code=status.HTTP_200_OK)
def verify_2fa_setup(
    request: Verify2FATokenRequest,
    current_user: User = Depends(get_current_user)
) -> dict:
    """Verify the 2FA token during setup."""
    if not current_user.two_factor_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA not properly initialized"
        )

    if verify_totp_token(current_user.two_factor_secret, request.token):
        return {"verified": True}
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid 2FA token"
        )


@router.post("/2fa/disable", status_code=status.HTTP_200_OK)
def disable_2fa(
    request: Disable2FARequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> dict:
    """Disable 2FA for the current user."""
    # Verify user password for security
    if not verify_password(request.password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid password"
        )

    # Disable 2FA
    current_user.two_factor_secret = None
    current_user.two_factor_enabled = False
    db.commit()

    return {"message": "2FA disabled successfully"}


@router.post("/2fa/authenticate", status_code=status.HTTP_200_OK)
def authenticate_with_2fa(
    request: Verify2FATokenRequest,
    current_user: User = Depends(get_current_user)
) -> dict:
    """Authenticate using 2FA token."""
    if not current_user.two_factor_enabled or not current_user.two_factor_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA not enabled for this account"
        )

    if verify_totp_token(current_user.two_factor_secret, request.token):
        return {"authenticated": True}
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid 2FA token"
        )


# Additional Security and Monitoring Endpoints
class RefreshTokenRequest(BaseModel):
    refresh_token: str


@router.post("/refresh", response_model=dict)
def refresh_access_token(
    request: RefreshTokenRequest,
    db: Session = Depends(get_db)
) -> dict:
    """Refresh access token using refresh token."""
    # Find the refresh token in the database
    refresh_token_record = db.query(RefreshToken).filter(
        RefreshToken.token == request.refresh_token
    ).first()

    if not refresh_token_record or refresh_token_record.is_revoked:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked refresh token"
        )

    if refresh_token_record.expires_at < datetime.utcnow():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has expired"
        )

    # Generate new access token for the user
    user = refresh_token_record.user
    new_access_token = create_access_token(data={"sub": str(user.id)})

    # Log the refresh event
    log_audit_event(db, user.id, "token_refresh", "auth.refresh",
                   {"token_id": refresh_token_record.id},
                   None, None)

    return {
        "access_token": new_access_token,
        "token_type": "bearer",
        "expires_in": settings.access_token_expire_minutes * 60
    }


@router.get("/security/login-attempts", response_model=list)
def get_login_attempts(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> list:
    """Get login attempts for the current user (admin can see all)."""
    # Check if user has admin privileges
    user_roles = [role.name for role in current_user.roles]

    if "admin" in user_roles:
        # Admin can see all login attempts
        attempts = db.query(LoginAttempt).order_by(LoginAttempt.created_at.desc()).limit(100).all()
    else:
        # Regular user can only see their own attempts
        attempts = db.query(LoginAttempt).filter(
            LoginAttempt.email == current_user.email
        ).order_by(LoginAttempt.created_at.desc()).limit(50).all()

    return [{
        "id": attempt.id,
        "email": attempt.email,
        "ip_address": attempt.ip_address,
        "user_agent": attempt.user_agent,
        "success": attempt.success,
        "failure_reason": attempt.failure_reason,
        "created_at": attempt.created_at
    } for attempt in attempts]


@router.get("/security/audit-log", response_model=list)
def get_audit_log(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> list:
    """Get audit log for the current user (admin can see all)."""
    # Check if user has admin privileges
    user_roles = [role.name for role in current_user.roles]

    if "admin" in user_roles:
        # Admin can see all audit logs
        logs = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(100).all()
    else:
        # Regular user can only see their own logs
        logs = db.query(AuditLog).filter(
            AuditLog.user_id == current_user.id
        ).order_by(AuditLog.created_at.desc()).limit(50).all()

    return [{
        "id": log.id,
        "user_id": log.user_id,
        "action": log.action,
        "resource": log.resource,
        "details": log.details,
        "ip_address": log.ip_address,
        "user_agent": log.user_agent,
        "created_at": log.created_at
    } for log in logs]
```

### Register Router in Main App

```python
from fastapi import FastAPI
from .auth_endpoints import router as auth_router

app = FastAPI()

# Register auth router
app.include_router(auth_router)
```

## Protecting Routes

Add authentication to any endpoint:

```python
from fastapi import Depends
from .auth_utils import get_current_user
from ..database.models import User

@app.get("/protected-endpoint")
async def protected_route(current_user: User = Depends(get_current_user)):
    """This endpoint requires authentication."""
    return {
        "message": "You are authenticated!",
        "user_id": current_user.id,
        "email": current_user.email
    }
```

## CORS Configuration

```python
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure for your domain in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

## SPA Routing Support

For React apps, serve index.html for frontend routes:

```python
from fastapi.responses import FileResponse
from pathlib import Path

dashboard_dir = Path(__file__).parent / "static" / "dashboard"

@app.get("/login")
async def serve_login():
    return FileResponse(dashboard_dir / "index.html")

@app.get("/register")
async def serve_register():
    return FileResponse(dashboard_dir / "index.html")

@app.get("/")
async def serve_root():
    return FileResponse(dashboard_dir / "index.html")
```
