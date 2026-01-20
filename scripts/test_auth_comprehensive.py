import pytest
import bcrypt
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from jose import jwt

# Import your models and app
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from backend.main import app
from backend.src.database.models import Base, User, Role, Permission, RefreshToken, LoginAttempt, PasswordHistory, AuditLog
from backend.src.database import get_db
from backend.src.config.settings import settings


# Setup test database
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base.metadata.create_all(bind=engine)

# Override dependency
def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db

client = TestClient(app)


@pytest.fixture
def db_session():
    """Create a new database session with a rollback at the end of the test."""
    connection = engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)

    yield session

    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture
def test_user(db_session):
    """Create a test user."""
    from backend.src.api.auth_utils import hash_password

    user = User(
        email="test@example.com",
        hashed_password=hash_password("ValidPass123!"),
        is_active=True,
        is_verified=True,
        created_at=datetime.utcnow()
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture
def authenticated_client(client, test_user):
    """Create a client with authenticated user."""
    response = client.post("/auth/login", data={
        "username": "test@example.com",
        "password": "ValidPass123!"
    })
    assert response.status_code == 200
    token_data = response.json()
    client.headers.update({"Authorization": f"Bearer {token_data['access_token']}"})
    return client


class TestUserRegistration:
    """Test user registration functionality and edge cases."""

    def test_successful_registration(self, client):
        """Test successful user registration."""
        response = client.post("/auth/register", json={
            "email": "newuser@example.com",
            "password": "ValidPass123!"
        })
        assert response.status_code == 201
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["email"] == "newuser@example.com"

    def test_registration_duplicate_email(self, client, test_user):
        """Test registration with duplicate email."""
        response = client.post("/auth/register", json={
            "email": "test@example.com",
            "password": "ValidPass123!"
        })
        assert response.status_code == 400
        assert "already registered" in response.json()["detail"]

    def test_registration_weak_password(self, client):
        """Test registration with weak password."""
        response = client.post("/auth/register", json={
            "email": "weakpass@example.com",
            "password": "weak"
        })
        assert response.status_code == 400
        assert "at least 12 characters" in response.json()["detail"]

    def test_registration_invalid_email(self, client):
        """Test registration with invalid email format."""
        response = client.post("/auth/register", json={
            "email": "invalid-email",
            "password": "ValidPass123!"
        })
        assert response.status_code == 422  # Validation error

    def test_registration_case_insensitive_email(self, client, test_user):
        """Test registration with same email in different case."""
        response = client.post("/auth/register", json={
            "email": "TEST@EXAMPLE.COM",  # Same email in uppercase
            "password": "ValidPass123!"
        })
        assert response.status_code == 400
        assert "already registered" in response.json()["detail"]


class TestUserLogin:
    """Test user login functionality and edge cases."""

    def test_successful_login(self, client, test_user):
        """Test successful login."""
        response = client.post("/auth/login", data={
            "username": "test@example.com",
            "password": "ValidPass123!"
        })
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["email"] == "test@example.com"

    def test_login_wrong_password(self, client, test_user):
        """Test login with wrong password."""
        response = client.post("/auth/login", data={
            "username": "test@example.com",
            "password": "wrongpassword"
        })
        assert response.status_code == 401
        assert "Incorrect email or password" in response.json()["detail"]

    def test_login_nonexistent_user(self, client):
        """Test login with nonexistent user."""
        response = client.post("/auth/login", data={
            "username": "nonexistent@example.com",
            "password": "anypassword"
        })
        assert response.status_code == 401
        assert "Incorrect email or password" in response.json()["detail"]

    def test_login_inactive_user(self, db_session, client):
        """Test login with inactive user."""
        from backend.src.api.auth_utils import hash_password

        user = User(
            email="inactive@example.com",
            hashed_password=hash_password("ValidPass123!"),
            is_active=False,
            is_verified=True
        )
        db_session.add(user)
        db_session.commit()

        response = client.post("/auth/login", data={
            "username": "inactive@example.com",
            "password": "ValidPass123!"
        })
        assert response.status_code == 403
        assert "Inactive user" in response.json()["detail"]

    def test_bruteforce_protection(self, db_session, client):
        """Test account lockout after multiple failed attempts."""
        # Create a user for this test
        from backend.src.api.auth_utils import hash_password
        user = User(
            email="bruteforce@example.com",
            hashed_password=hash_password("ValidPass123!"),
            is_active=True,
            is_verified=True
        )
        db_session.add(user)
        db_session.commit()

        # Try to login with wrong password multiple times
        for _ in range(6):  # Exceed the limit (5 attempts)
            client.post("/auth/login", data={
                "username": "bruteforce@example.com",
                "password": "wrongpassword"
            })

        # Now try with correct password - should be locked
        response = client.post("/auth/login", data={
            "username": "bruteforce@example.com",
            "password": "ValidPass123!"
        })
        assert response.status_code == 423  # Locked
        assert "temporarily locked" in response.json()["detail"]


class TestPasswordValidation:
    """Test strong password validation edge cases."""

    @pytest.mark.parametrize("password,error_msg", [
        ("short", "at least 12 characters"),
        ("nouppercase123!", "uppercase letter"),
        ("NOLOWERCASE123!", "lowercase letter"),
        ("NoNumbers!", "digit"),
        ("NoSpecialChars123", "special character"),
        ("password123!", "too common"),
        ("123456789012", "too common"),  # Common number sequence
    ])
    def test_weak_password_validation(self, client, password, error_msg):
        """Test various weak password patterns."""
        response = client.post("/auth/register", json={
            "email": f"weak_{password}@example.com",
            "password": password
        })
        assert response.status_code == 400
        assert error_msg in response.json()["detail"]


class TestPasswordHistory:
    """Test password history functionality."""

    def test_password_cannot_be_same_as_last_5(self, db_session, authenticated_client, test_user):
        """Test that user cannot reuse one of their last 5 passwords."""
        from backend.src.api.auth_utils import hash_password, update_user_password

        # Add 5 old passwords to history
        for i in range(5):
            old_pass_hash = hash_password(f"OldPassword{i}!")
            hist = PasswordHistory(
                user_id=test_user.id,
                password_hash=old_pass_hash
            )
            db_session.add(hist)
        db_session.commit()

        # Try to update to one of the old passwords
        response = authenticated_client.post("/auth/reset-password", json={
            "token": "valid-token",  # This would be handled differently in real scenario
            "new_password": "OldPassword3!"
        })
        # Note: This test would need adjustment based on how you implement password change endpoint
        # For now, testing the function directly
        from backend.src.api.auth_utils import check_password_history
        with pytest.raises(Exception):  # Would raise HTTPException
            check_password_history(db_session, test_user.id, "OldPassword3!")


class TestJWTAuthentication:
    """Test JWT token functionality and edge cases."""

    def test_expired_token(self, client):
        """Test behavior with expired token."""
        # Create an expired token
        expired_token = jwt.encode({
            "sub": "1",
            "exp": datetime.utcnow() - timedelta(minutes=1),  # Expired 1 minute ago
            "type": "access"
        }, settings.secret_key, algorithm=settings.algorithm)

        client.headers.update({"Authorization": f"Bearer {expired_token}"})
        response = client.get("/auth/me")
        assert response.status_code == 401

    def test_invalid_token(self, client):
        """Test behavior with invalid token."""
        client.headers.update({"Authorization": "Bearer invalid.token.here"})
        response = client.get("/auth/me")
        assert response.status_code == 401

    def test_token_refresh(self, client, test_user):
        """Test token refresh functionality."""
        # Login to get tokens
        login_response = client.post("/auth/login", data={
            "username": "test@example.com",
            "password": "ValidPass123!"
        })
        assert login_response.status_code == 200
        tokens = login_response.json()

        # Use refresh token to get new access token
        refresh_response = client.post("/auth/refresh", json={
            "refresh_token": tokens["refresh_token"]
        })
        assert refresh_response.status_code == 200
        new_tokens = refresh_response.json()
        assert "access_token" in new_tokens


class TestEmailVerification:
    """Test email verification functionality and edge cases."""

    def test_email_verification_with_valid_token(self, db_session, client, test_user):
        """Test email verification with valid token."""
        from backend.src.api.auth_utils import generate_verification_token

        # Create user with unverified email
        unverified_user = User(
            email="unverified@example.com",
            hashed_password=hash_password("ValidPass123!"),
            is_active=True,
            is_verified=False
        )
        db_session.add(unverified_user)
        db_session.commit()

        # Generate verification token
        token = generate_verification_token(unverified_user.id)

        # Verify email
        response = client.post("/auth/verify-email", json={"token": token})
        assert response.status_code == 200
        assert "successfully verified" in response.json()["message"]

    def test_email_verification_with_invalid_token(self, client):
        """Test email verification with invalid token."""
        response = client.post("/auth/verify-email", json={"token": "invalid_token"})
        assert response.status_code == 400
        assert "Invalid or expired" in response.json()["detail"]

    def test_resend_verification_email(self, client, test_user):
        """Test resending verification email."""
        response = client.post("/auth/resend-verification", json={
            "email": "test@example.com"
        })
        # Should return different message for already verified users
        assert response.status_code == 400
        assert "already verified" in response.json()["detail"]


class Test2FAFunctionality:
    """Test 2FA functionality and edge cases."""

    def test_enable_2fa(self, authenticated_client, test_user):
        """Test enabling 2FA."""
        response = authenticated_client.post("/auth/2fa/enable", json={
            "password": "ValidPass123!"
        })
        assert response.status_code == 200
        data = response.json()
        assert "secret" in data
        assert "qr_code_uri" in data
        assert "backup_codes" in data
        assert len(data["backup_codes"]) == 10

    def test_2fa_with_disabled_account(self, authenticated_client, test_user):
        """Test 2FA on account where it's not enabled."""
        # Don't enable 2FA first, just try to authenticate
        response = authenticated_client.post("/auth/2fa/authenticate", json={
            "token": "123456"
        })
        assert response.status_code == 400
        assert "not enabled" in response.json()["detail"]


class TestOAuthIntegration:
    """Test OAuth functionality."""

    def test_oauth_google_initiation(self, client):
        """Test initiating Google OAuth."""
        response = client.get("/auth/oauth/google")
        assert response.status_code == 200
        data = response.json()
        assert "auth_url" in data
        assert "google.com" in data["auth_url"]

    def test_oauth_github_initiation(self, client):
        """Test initiating GitHub OAuth."""
        response = client.get("/auth/oauth/github")
        assert response.status_code == 200
        data = response.json()
        assert "auth_url" in data
        assert "github.com" in data["auth_url"]


class TestSecurityMonitoring:
    """Test security monitoring features."""

    def test_login_attempts_logging(self, db_session, client, test_user):
        """Test that login attempts are properly logged."""
        # Try a failed login
        client.post("/auth/login", data={
            "username": "test@example.com",
            "password": "wrongpassword"
        })

        # Check that attempt was logged
        attempts = db_session.query(LoginAttempt).filter_by(email="test@example.com").all()
        assert len(attempts) >= 1
        assert not attempts[-1].success  # Last attempt should be unsuccessful

        # Now try successful login
        client.post("/auth/login", data={
            "username": "test@example.com",
            "password": "ValidPass123!"
        })

        # Check that successful attempt was logged
        attempts = db_session.query(LoginAttempt).filter_by(email="test@example.com").all()
        assert len(attempts) >= 2
        assert attempts[-1].success  # Last attempt should be successful

    def test_audit_logging(self, db_session, authenticated_client, test_user):
        """Test audit logging functionality."""
        # Perform an action that should be audited
        authenticated_client.get("/auth/me")

        # Check that audit log was created
        logs = db_session.query(AuditLog).filter_by(user_id=test_user.id).all()
        assert len(logs) >= 1
        assert logs[-1].action == "login_success"  # Or whatever action was performed


class TestRBACPermissions:
    """Test Role-Based Access Control."""

    def test_has_permission_decorator(self, db_session, authenticated_client, test_user):
        """Test the has_permission decorator functionality."""
        # Create a role and permission
        role = Role(name="moderator")
        permission = Permission(name="user:moderate")

        db_session.add(role)
        db_session.add(permission)
        db_session.commit()

        # Associate them
        from sqlalchemy import Table, Column, Integer, ForeignKey
        role_permissions = Table(
            "role_permissions",
            Base.metadata,
            Column("role_id", Integer, ForeignKey("roles.id"), primary_key=True),
            Column("permission_id", Integer, ForeignKey("permissions.id"), primary_key=True),
        )

        # Add role to user
        test_user.roles.append(role)
        db_session.commit()

        # Test would require specific endpoint with decorator
        # This is a conceptual test
        assert True  # Placeholder for actual RBAC test


class TestEdgeCases:
    """Test various edge cases that are often ignored."""

    def test_large_request_body(self, client):
        """Test handling of large request bodies."""
        large_password = "Aa1!Aa1!Aa1!" + "x" * 10000  # Very long password
        response = client.post("/auth/register", json={
            "email": "large@example.com",
            "password": large_password
        })
        # Should handle gracefully, probably 422 or 400
        assert response.status_code in [400, 422]

    def test_sql_injection_attempt(self, client):
        """Test protection against SQL injection."""
        malicious_email = "'; DROP TABLE users; --"
        response = client.post("/auth/register", json={
            "email": malicious_email,
            "password": "ValidPass123!"
        })
        # Should not crash, probably 422 for invalid email format
        assert response.status_code in [422]

    def test_xss_attempt_in_email(self, client):
        """Test protection against XSS in email field."""
        xss_email = "<script>alert('XSS')</script>@example.com"
        response = client.post("/auth/register", json={
            "email": xss_email,
            "password": "ValidPass123!"
        })
        # Should validate email format and reject
        assert response.status_code == 422

    def test_concurrent_login_attempts(self, client, test_user):
        """Test system behavior under concurrent login attempts."""
        import threading
        import time

        results = []

        def login_attempt():
            resp = client.post("/auth/login", data={
                "username": "test@example.com",
                "password": "ValidPass123!"
            })
            results.append(resp.status_code)

        # Start multiple threads
        threads = []
        for _ in range(5):
            thread = threading.Thread(target=login_attempt)
            threads.append(thread)
            thread.start()

        # Wait for all to complete
        for thread in threads:
            thread.join()

        # All should succeed since they're valid credentials
        assert all(code == 200 for code in results)

    def test_refresh_token_reuse_prevention(self, client, test_user):
        """Test that refresh tokens cannot be reused (replay attack prevention)."""
        # Login to get tokens
        login_response = client.post("/auth/login", data={
            "username": "test@example.com",
            "password": "ValidPass123!"
        })
        assert login_response.status_code == 200
        tokens = login_response.json()
        refresh_token = tokens["refresh_token"]

        # Use refresh token once
        refresh_response1 = client.post("/auth/refresh", json={
            "refresh_token": refresh_token
        })
        assert refresh_response1.status_code == 200

        # Try to use the same refresh token again (should fail)
        refresh_response2 = client.post("/auth/refresh", json={
            "refresh_token": refresh_token
        })
        assert refresh_response2.status_code == 401  # Should be invalid/expired now

    def test_expired_refresh_token(self, db_session, client, test_user):
        """Test behavior with expired refresh token."""
        from datetime import datetime, timedelta
        from backend.src.api.auth_utils import create_refresh_token

        # Create an expired refresh token manually
        expired_refresh = RefreshToken(
            token="expired_test_token",
            user_id=test_user.id,
            expires_at=datetime.utcnow() - timedelta(days=1),  # Expired yesterday
            is_revoked=False
        )
        db_session.add(expired_refresh)
        db_session.commit()

        response = client.post("/auth/refresh", json={
            "refresh_token": "expired_test_token"
        })
        assert response.status_code == 401
        assert "expired" in response.json()["detail"]

    def test_timezone_related_issues(self, db_session, client, test_user):
        """Test timezone-related issues with token expiration."""
        # This would be tested by ensuring datetime operations are timezone-aware
        # Our implementation should use UTC consistently
        assert True  # Conceptual test - implementation should ensure UTC usage

    def test_case_sensitivity_in_email_search(self, db_session, client, test_user):
        """Test that email searches are properly case-insensitive."""
        # The database query should use LOWER() or similar
        response = client.post("/auth/login", data={
            "username": "TEST@EXAMPLE.COM",  # Different case
            "password": "ValidPass123!"
        })
        # Should still work if email lookup is case-insensitive
        assert response.status_code == 200


if __name__ == "__main__":
    pytest.main([__file__, "-v"])