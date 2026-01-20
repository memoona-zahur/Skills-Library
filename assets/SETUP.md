# Requirements for FastAPI + React Authentication

## Backend Dependencies

Add to your `requirements.txt`:

```
# Authentication
passlib[bcrypt]>=1.7.4
python-jose[cryptography]>=3.3.0
pydantic[email]>=2.6.0

# FastAPI & Database
fastapi>=0.104.0
uvicorn>=0.24.0
sqlalchemy>=2.0.0
pydantic-settings>=2.0.0

# Database drivers (choose one)
psycopg2-binary>=2.9.0  # PostgreSQL
# OR
# pymysql>=1.1.0  # MySQL
```

Install with:
```bash
pip install -r requirements.txt
```

## Frontend Dependencies

Add to your `package.json`:

```json
{
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-router-dom": "^6.20.0",
    "axios": "^1.6.0"
  },
  "devDependencies": {
    "@types/react": "^18.2.0",
    "@types/react-dom": "^18.2.0",
    "@vitejs/plugin-react": "^4.2.0",
    "typescript": "^5.3.0",
    "vite": "^5.0.0"
  }
}
```

Install with:
```bash
npm install
```

## Environment Variables

### Backend `.env`

```env
# JWT Configuration
SECRET_KEY=your-secret-key-here-generate-with-openssl-rand-hex-32
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=10080

# Database
DATABASE_URL=postgresql://user:password@localhost:5432/dbname

# Environment
ENVIRONMENT=development
```

### Frontend `.env`

```env
# API Configuration
VITE_API_URL=http://localhost:8000
```

## Generate SECRET_KEY

Use OpenSSL to generate a secure secret key:

```bash
openssl rand -hex 32
```

Copy the output and set it as your SECRET_KEY in the backend `.env` file.

## Database Setup

### PostgreSQL

```bash
# Create database
createdb your_database_name

# Or using psql
psql -U postgres
CREATE DATABASE your_database_name;
```

### Initialize Tables

The User table will be created automatically when you run the FastAPI application with the `init_db()` function in the lifespan handler.

## Verify Installation

### Backend

```bash
# Start FastAPI server
uvicorn backend.src.api.main:app --reload --port 8000
```

Visit: http://localhost:8000/docs to see API documentation

### Frontend

```bash
# Start Vite dev server
npm run dev
```

Visit: http://localhost:5173 to see the application

## Production Deployment

### Backend

1. Set environment variables in your hosting platform
2. Use a production WSGI server (gunicorn, uvicorn with workers)
3. Enable HTTPS
4. Configure CORS for your domain

### Frontend

1. Build the production bundle: `npm run build`
2. Copy `dist/` contents to backend `static/` directory
3. Configure backend to serve static files
4. Set production API URL in environment variables

## Security Checklist

- [ ] SECRET_KEY is randomly generated and stored securely
- [ ] Database credentials are in environment variables
- [ ] HTTPS is enabled in production
- [ ] CORS is configured for specific domains (not "*")
- [ ] Password requirements are enforced
- [ ] Token expiration is set appropriately
- [ ] API rate limiting is configured (optional but recommended)
