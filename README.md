# Secure Login System

## Features
- FastAPI backend with JWT access tokens + httpOnly refresh cookie
- Password hashing (bcrypt)
- Refresh token rotation & server-side revocation
- React frontend (simple) demonstrating login/register flows

## Run locally (dev)
1. Copy `.env.example` to `.env` and set SECRET_KEY.
2. Start Postgres and backend:
   - Option A: With docker-compose: `docker-compose up --build`
   - Option B: Run Postgres locally and run backend with uvicorn
3. Install frontend deps: `cd frontend && npm install`
4. Run frontend: `npm run dev` and open http://localhost:3000

## Notes
- In production: set `secure=True` for cookies, enable HTTPS, set strong CORS origins, rate-limit auth endpoints, add email verification, enable logging and monitoring, and use Alembic for migrations.
