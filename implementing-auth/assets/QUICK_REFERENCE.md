# Quick Reference Guide

## Authentication Flow Summary

```
Registration: Email + Password → Hash Password → Store User → Return JWT
Login: Email + Password → Verify → Return JWT
Protected Access: Request + JWT → Verify Token → Return Data
Logout: Clear Token → Redirect to Login
```

## Backend Quick Commands

```python
# Hash password
from passlib.context import CryptContext
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
hashed = pwd_context.hash("password123")

# Create JWT token
from jose import jwt
from datetime import datetime, timedelta
token = jwt.encode(
    {"sub": "user_id", "exp": datetime.utcnow() + timedelta(days=7)},
    "secret_key",
    algorithm="HS256"
)

# Verify JWT token
from jose import jwt, JWTError
try:
    payload = jwt.decode(token, "secret_key", algorithms=["HS256"])
    user_id = payload.get("sub")
except JWTError:
    # Invalid token
    pass

# Protect endpoint
from fastapi import Depends
from .auth_utils import get_current_user

@app.get("/protected")
async def protected(current_user = Depends(get_current_user)):
    return {"user_id": current_user.id}
```

## Frontend Quick Commands

```typescript
// Login
import { login } from './services/auth';
const response = await login({ username: email, password });
localStorage.setItem('access_token', response.access_token);

// Logout
localStorage.removeItem('access_token');
localStorage.removeItem('user_id');
localStorage.removeItem('user_email');
localStorage.removeItem('token_expiry');

// Check if authenticated
const token = localStorage.getItem('access_token');
const isAuthenticated = !!token;

// Add token to request
axios.get('/api/endpoint', {
  headers: { Authorization: `Bearer ${token}` }
});

// Protected route
<Route path="/dashboard" element={
  <ProtectedRoute>
    <Dashboard />
  </ProtectedRoute>
} />
```

## Common Patterns

### Backend: Create User

```python
from .auth_utils import hash_password
from ..database.models import User

def create_user(db: Session, email: str, password: str):
    hashed_password = hash_password(password)
    user = User(email=email, hashed_password=hashed_password)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user
```

### Backend: Authenticate User

```python
from .auth_utils import verify_password

def authenticate_user(db: Session, email: str, password: str):
    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(password, user.hashed_password):
        return None
    return user
```

### Frontend: Auth Context Usage

```typescript
import { useAuth } from './hooks/useAuth';

function MyComponent() {
  const { isAuthenticated, user, login, logout } = useAuth();

  if (!isAuthenticated) {
    return <div>Please login</div>;
  }

  return (
    <div>
      <p>Welcome {user.email}</p>
      <button onClick={logout}>Logout</button>
    </div>
  );
}
```

### Frontend: Protected API Call

```typescript
import api from './services/api';

// Token is automatically added by interceptor
const response = await api.get('/api/protected-endpoint');
```

## Troubleshooting

### 401 Unauthorized
- Check token is being sent in Authorization header
- Verify token hasn't expired
- Ensure SECRET_KEY matches between token creation and verification

### CORS Errors
- Configure CORS middleware in FastAPI
- Set correct origins (not "*" in production)
- Enable credentials if needed

### Token Not Persisting
- Check localStorage is working
- Verify token is being stored after login
- Check browser privacy settings

### Password Not Hashing
- Ensure passlib[bcrypt] is installed
- Verify pwd_context is configured correctly
- Check hash_password function is being called

### Routes Not Working
- Verify React Router is configured
- Check backend serves index.html for SPA routes
- Ensure route guards are properly implemented

## Testing Checklist

- [ ] Register new user
- [ ] Login with valid credentials
- [ ] Login with invalid credentials (should fail)
- [ ] Access protected route without token (should redirect)
- [ ] Access protected route with token (should work)
- [ ] Logout and verify token is cleared
- [ ] Token expiration handling
- [ ] Password is hashed in database
- [ ] User can't see other users' data (if applicable)

## Security Checklist

- [ ] SECRET_KEY is random and secure
- [ ] Passwords are hashed with bcrypt
- [ ] Tokens have expiration
- [ ] HTTPS in production
- [ ] CORS configured properly
- [ ] SQL injection protection (use ORM)
- [ ] XSS protection (sanitize inputs)
- [ ] Rate limiting (optional)

## File Structure

```
backend/
├── src/
│   ├── api/
│   │   ├── main.py (FastAPI app)
│   │   ├── auth_endpoints.py (auth routes)
│   │   └── auth_utils.py (JWT & password utils)
│   ├── config/
│   │   └── settings.py (configuration)
│   └── database/
│       ├── models.py (User model)
│       └── __init__.py (db session)
└── requirements.txt

frontend/
├── src/
│   ├── components/
│   │   └── Auth/
│   │       ├── Login.tsx
│   │       └── Register.tsx
│   ├── hooks/
│   │   └── useAuth.tsx (auth context)
│   ├── services/
│   │   ├── auth.ts (auth API)
│   │   └── api.ts (main API with interceptors)
│   ├── types/
│   │   ├── auth.ts (auth types)
│   │   └── index.ts
│   └── App.tsx (routes & guards)
├── package.json
└── vite.config.ts
```

## Environment Variables

### Backend (.env)
```
SECRET_KEY=<generate-with-openssl-rand-hex-32>
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=10080
DATABASE_URL=postgresql://user:pass@host:port/db
```

### Frontend (.env)
```
VITE_API_URL=http://localhost:8000
```

## API Endpoints

```
POST   /auth/register    - Create new user
POST   /auth/login       - Authenticate user
GET    /auth/me          - Get current user
POST   /auth/logout      - Logout (client-side)
```

## Token Format

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "user_id": 1,
  "email": "user@example.com",
  "expires_in": 604800
}
```

## Request Headers

```
Authorization: Bearer <token>
Content-Type: application/json
```

## Response Codes

- 200: Success
- 201: Created (registration)
- 400: Bad request (validation error)
- 401: Unauthorized (invalid credentials/token)
- 403: Forbidden (inactive user)
- 500: Server error
