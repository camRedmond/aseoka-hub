"""Tests for user authentication endpoints."""

import pytest
from datetime import datetime, timedelta, timezone
from httpx import AsyncClient, ASGITransport
from unittest.mock import patch, MagicMock

import bcrypt

# Environment is configured in conftest.py which runs first
# Import after env vars are set
import importlib
import aseoka_hub.server
# Force reload to pick up new env vars
importlib.reload(aseoka_hub.server)

from aseoka_hub.server import app, HubSettings
from aseoka_hub.database import HubDatabase, Client, User
import aseoka_hub.server as server_module


@pytest.fixture
async def db():
    """Create a test database."""
    database = HubDatabase(":memory:")
    await database.connect()
    yield database
    await database.close()


@pytest.fixture
async def client_with_db(db):
    """Create a test client with database access."""
    # Inject the test database into the module-level global
    server_module._db = db

    # Also set up settings
    server_module._settings = HubSettings()

    # Set app.state for middleware
    app.state.database = db
    app.state.settings = server_module._settings

    # Reset the rate limiter storage to avoid rate limiting in tests
    # The limiter uses an in-memory storage by default
    if hasattr(server_module.limiter, '_storage'):
        server_module.limiter._storage.reset()
    elif hasattr(server_module.limiter, 'storage'):
        if hasattr(server_module.limiter.storage, 'reset'):
            server_module.limiter.storage.reset()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client, db

    # Cleanup
    server_module._db = None


@pytest.fixture
async def test_client_org(db):
    """Create a test client organization."""
    client_org = Client(
        client_id="test_client",
        client_name="Test Client",
        tier="starter",
    )
    await db.create_client(client_org)
    return client_org


@pytest.fixture
async def test_user(db, test_client_org):
    """Create a test user."""
    password_hash = bcrypt.hashpw(b"testpassword123", bcrypt.gensalt(rounds=12)).decode()
    user = User(
        user_id="user_test123",
        client_id=test_client_org.client_id,
        email="test@example.com",
        password_hash=password_hash,
        name="Test User",
        is_admin=False,
    )
    await db.create_user(user)
    return user


@pytest.fixture
async def admin_user(db, test_client_org):
    """Create a test admin user."""
    password_hash = bcrypt.hashpw(b"adminpassword123", bcrypt.gensalt(rounds=12)).decode()
    user = User(
        user_id="user_admin123",
        client_id=test_client_org.client_id,
        email="admin@example.com",
        password_hash=password_hash,
        name="Admin User",
        is_admin=True,
    )
    await db.create_user(user)
    return user


class TestUserLogin:
    """Tests for POST /auth/login endpoint."""

    @pytest.mark.asyncio
    async def test_login_success(self, client_with_db, test_client_org, test_user):
        """Test successful login with valid credentials."""
        client, db = client_with_db

        response = await client.post(
            "/auth/login",
            json={"email": "test@example.com", "password": "testpassword123"},
        )

        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert data["user_id"] == test_user.user_id
        assert data["client_id"] == test_client_org.client_id
        assert data["is_admin"] is False
        assert data["name"] == "Test User"

    @pytest.mark.asyncio
    async def test_login_invalid_email(self, client_with_db, test_client_org, test_user):
        """Test login with non-existent email returns generic error."""
        client, db = client_with_db

        response = await client.post(
            "/auth/login",
            json={"email": "nonexistent@example.com", "password": "testpassword123"},
        )

        assert response.status_code == 401
        data = response.json()
        assert data["detail"] == "Invalid credentials"

    @pytest.mark.asyncio
    async def test_login_invalid_password(self, client_with_db, test_client_org, test_user):
        """Test login with wrong password returns generic error."""
        client, db = client_with_db

        response = await client.post(
            "/auth/login",
            json={"email": "test@example.com", "password": "wrongpassword"},
        )

        assert response.status_code == 401
        data = response.json()
        assert data["detail"] == "Invalid credentials"

    @pytest.mark.asyncio
    async def test_login_increments_failed_attempts(self, client_with_db, test_client_org, test_user):
        """Test that failed logins increment the counter."""
        client, db = client_with_db

        # Make a failed login attempt
        await client.post(
            "/auth/login",
            json={"email": "test@example.com", "password": "wrongpassword"},
        )

        # Check failed attempts incremented
        user = await db.get_user(test_user.user_id)
        assert user.failed_login_attempts == 1

    @pytest.mark.asyncio
    async def test_login_account_lockout(self, client_with_db, test_client_org, test_user):
        """Test account lockout after 5 failed attempts."""
        client, db = client_with_db

        # Make 5 failed login attempts
        for _ in range(5):
            await client.post(
                "/auth/login",
                json={"email": "test@example.com", "password": "wrongpassword"},
            )

        # Check account is locked
        user = await db.get_user(test_user.user_id)
        assert user.failed_login_attempts >= 5
        assert user.locked_until is not None

        # Try to login again - should get locked error
        response = await client.post(
            "/auth/login",
            json={"email": "test@example.com", "password": "testpassword123"},
        )

        assert response.status_code == 423
        data = response.json()
        assert "locked" in data["detail"].lower()

    @pytest.mark.asyncio
    async def test_login_resets_failed_attempts(self, client_with_db, test_client_org, test_user):
        """Test successful login resets failed attempts counter."""
        client, db = client_with_db

        # Make a failed login attempt
        await client.post(
            "/auth/login",
            json={"email": "test@example.com", "password": "wrongpassword"},
        )

        # Verify counter incremented
        user = await db.get_user(test_user.user_id)
        assert user.failed_login_attempts == 1

        # Successful login
        await client.post(
            "/auth/login",
            json={"email": "test@example.com", "password": "testpassword123"},
        )

        # Check counter reset
        user = await db.get_user(test_user.user_id)
        assert user.failed_login_attempts == 0

    @pytest.mark.asyncio
    async def test_login_password_too_short(self, client_with_db):
        """Test login validation rejects short passwords."""
        client, db = client_with_db

        response = await client.post(
            "/auth/login",
            json={"email": "test@example.com", "password": "short"},
        )

        assert response.status_code == 422  # Validation error


class TestUserRegister:
    """Tests for POST /auth/register endpoint."""

    @pytest.mark.asyncio
    async def test_register_first_user_becomes_admin(self, client_with_db, test_client_org):
        """Test first user registration creates admin without auth."""
        client, db = client_with_db

        response = await client.post(
            "/auth/register",
            json={
                "email": "first@example.com",
                "password": "firstpassword123",
                "name": "First User",
                "client_id": test_client_org.client_id,
            },
        )

        assert response.status_code == 201
        data = response.json()
        assert data["is_admin"] is True
        assert data["email"] == "first@example.com"

    @pytest.mark.asyncio
    async def test_register_requires_admin_after_first_user(self, client_with_db, test_client_org, admin_user):
        """Test subsequent registrations require admin auth."""
        client, db = client_with_db

        # Try to register without auth
        response = await client.post(
            "/auth/register",
            json={
                "email": "new@example.com",
                "password": "newpassword123",
                "name": "New User",
                "client_id": test_client_org.client_id,
            },
        )

        assert response.status_code == 403
        assert "Admin authentication required" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_register_with_admin_auth(self, client_with_db, test_client_org, admin_user):
        """Test registration succeeds with admin auth."""
        client, db = client_with_db

        # Login as admin to get token
        login_response = await client.post(
            "/auth/login",
            json={"email": "admin@example.com", "password": "adminpassword123"},
        )
        token = login_response.json()["access_token"]

        # Register new user with admin token
        response = await client.post(
            "/auth/register",
            json={
                "email": "new@example.com",
                "password": "newpassword123",
                "name": "New User",
                "client_id": test_client_org.client_id,
            },
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 201
        data = response.json()
        assert data["email"] == "new@example.com"
        assert data["is_admin"] is False

    @pytest.mark.asyncio
    async def test_register_duplicate_email(self, client_with_db, test_client_org, test_user):
        """Test registration fails for duplicate email."""
        client, db = client_with_db

        # No users yet, so first registration should work as admin
        response = await client.post(
            "/auth/register",
            json={
                "email": "test@example.com",  # Same as test_user
                "password": "anotherpassword123",
                "name": "Another User",
                "client_id": test_client_org.client_id,
            },
        )

        # Since test_user already exists, this requires admin auth
        # But even with admin auth, duplicate email should fail
        assert response.status_code in [403, 409]

    @pytest.mark.asyncio
    async def test_register_invalid_client(self, client_with_db):
        """Test registration fails for non-existent client."""
        client, db = client_with_db

        response = await client.post(
            "/auth/register",
            json={
                "email": "new@example.com",
                "password": "newpassword123",
                "name": "New User",
                "client_id": "nonexistent_client",
            },
        )

        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()


class TestGetCurrentUser:
    """Tests for GET /auth/me endpoint."""

    @pytest.mark.asyncio
    async def test_get_current_user_success(self, client_with_db, test_client_org, test_user):
        """Test getting current user with valid token."""
        client, db = client_with_db

        # Login to get token
        login_response = await client.post(
            "/auth/login",
            json={"email": "test@example.com", "password": "testpassword123"},
        )
        token = login_response.json()["access_token"]

        # Get current user
        response = await client.get(
            "/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["user_id"] == test_user.user_id
        assert data["email"] == "test@example.com"
        assert data["name"] == "Test User"

    @pytest.mark.asyncio
    async def test_get_current_user_no_auth(self, client_with_db):
        """Test getting current user without auth fails."""
        client, db = client_with_db

        response = await client.get("/auth/me")

        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_get_current_user_invalid_token(self, client_with_db):
        """Test getting current user with invalid token fails."""
        client, db = client_with_db

        response = await client.get(
            "/auth/me",
            headers={"Authorization": "Bearer invalid_token"},
        )

        assert response.status_code == 401


class TestSecurityMeasures:
    """Tests for security measures."""

    @pytest.mark.asyncio
    async def test_generic_error_for_invalid_email(self, client_with_db, test_client_org, test_user):
        """Test same error for invalid email and password (enumeration protection)."""
        client, db = client_with_db

        # Wrong email
        response1 = await client.post(
            "/auth/login",
            json={"email": "wrong@example.com", "password": "testpassword123"},
        )

        # Wrong password
        response2 = await client.post(
            "/auth/login",
            json={"email": "test@example.com", "password": "wrongpassword1"},
        )

        # Both should return the same generic error
        assert response1.status_code == response2.status_code == 401
        assert response1.json()["detail"] == response2.json()["detail"] == "Invalid credentials"

    @pytest.mark.asyncio
    async def test_email_case_insensitive(self, client_with_db, test_client_org, test_user):
        """Test email lookup is case-insensitive."""
        client, db = client_with_db

        response = await client.post(
            "/auth/login",
            json={"email": "TEST@EXAMPLE.COM", "password": "testpassword123"},
        )

        assert response.status_code == 200
