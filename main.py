from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional
import psycopg2
import psycopg2.extras  # lets us access columns by name
import hashlib
import secrets
import time
import os

app = FastAPI(title="Campus App")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with your frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()

# ---------- DATABASE SETUP ----------

def get_db():
    """Connect to the PostgreSQL database using Railway's DATABASE_URL env variable."""
    database_url = os.environ["DATABASE_URL"]

    # Railway gives a URL starting with "postgres://" but psycopg2 needs "postgresql://"
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)

    conn = psycopg2.connect(database_url, cursor_factory=psycopg2.extras.RealDictCursor)
    return conn

def init_db():
    """Create tables if they don't exist yet."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            display_name TEXT NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at DOUBLE PRECISION NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS campus_status (
            user_id INTEGER PRIMARY KEY,
            is_on_campus BOOLEAN NOT NULL DEFAULT FALSE,
            expires_at DOUBLE PRECISION,
            updated_at DOUBLE PRECISION NOT NULL
        )
    """)
    conn.commit()
    cur.close()
    conn.close()

init_db()

# ---------- HELPERS ----------

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def create_session(user_id: int) -> str:
    token = secrets.token_hex(32)
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO sessions (token, user_id, created_at) VALUES (%s, %s, %s)",
        (token, user_id, time.time())
    )
    conn.commit()
    cur.close()
    conn.close()
    return token

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT user_id FROM sessions WHERE token = %s", (token,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    if not row:
        raise HTTPException(status_code=401, detail="Invalid or expired token. Please log in again.")
    return row["user_id"]

# ---------- REQUEST MODELS ----------

class RegisterRequest(BaseModel):
    username: str
    password: str
    display_name: str

class LoginRequest(BaseModel):
    username: str
    password: str

class StatusUpdateRequest(BaseModel):
    is_on_campus: bool
    duration_minutes: Optional[int] = None

# ---------- ROUTES ----------

@app.post("/register")
def register(req: RegisterRequest):
    if len(req.username) < 3:
        raise HTTPException(status_code=400, detail="Username must be at least 3 characters.")
    if len(req.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters.")
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO users (username, password_hash, display_name) VALUES (%s, %s, %s)",
            (req.username.lower(), hash_password(req.password), req.display_name)
        )
        conn.commit()
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        raise HTTPException(status_code=400, detail="That username is already taken.")
    finally:
        cur.close()
        conn.close()
    return {"message": "Account created! You can now log in."}

@app.post("/login")
def login(req: LoginRequest):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, display_name FROM users WHERE username = %s AND password_hash = %s",
        (req.username.lower(), hash_password(req.password))
    )
    user = cur.fetchone()
    cur.close()
    conn.close()
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password.")
    token = create_session(user["id"])
    return {"token": token, "display_name": user["display_name"], "user_id": user["id"]}

@app.post("/logout")
def logout(user_id: int = Depends(get_current_user), credentials: HTTPAuthorizationCredentials = Depends(security)):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM sessions WHERE token = %s", (credentials.credentials,))
    conn.commit()
    cur.close()
    conn.close()
    return {"message": "Logged out."}

@app.post("/status")
def update_status(req: StatusUpdateRequest, user_id: int = Depends(get_current_user)):
    now = time.time()
    expires_at = None
    if req.is_on_campus and req.duration_minutes:
        expires_at = now + req.duration_minutes * 60
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO campus_status (user_id, is_on_campus, expires_at, updated_at)
        VALUES (%s, %s, %s, %s)
        ON CONFLICT (user_id) DO UPDATE SET
            is_on_campus = EXCLUDED.is_on_campus,
            expires_at = EXCLUDED.expires_at,
            updated_at = EXCLUDED.updated_at
    """, (user_id, req.is_on_campus, expires_at, now))
    conn.commit()
    cur.close()
    conn.close()
    return {"message": "Status updated."}

@app.get("/status/me")
def get_my_status(user_id: int = Depends(get_current_user)):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT is_on_campus, expires_at FROM campus_status WHERE user_id = %s", (user_id,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    if not row:
        return {"is_on_campus": False, "expires_at": None}
    now = time.time()
    if row["expires_at"] and now > row["expires_at"]:
        return {"is_on_campus": False, "expires_at": None}
    return {"is_on_campus": row["is_on_campus"], "expires_at": row["expires_at"]}

@app.get("/users")
def get_all_users(user_id: int = Depends(get_current_user)):
    now = time.time()
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT
            u.id,
            u.display_name,
            COALESCE(cs.is_on_campus, FALSE) AS is_on_campus,
            cs.expires_at,
            cs.updated_at
        FROM users u
        LEFT JOIN campus_status cs ON u.id = cs.user_id
        ORDER BY cs.is_on_campus DESC NULLS LAST, u.display_name ASC
    """)
    users = cur.fetchall()
    cur.close()
    conn.close()
    result = []
    for u in users:
        is_on = bool(u["is_on_campus"])
        if is_on and u["expires_at"] and now > u["expires_at"]:
            is_on = False
        result.append({
            "id": u["id"],
            "display_name": u["display_name"],
            "is_on_campus": is_on,
            "expires_at": u["expires_at"],
            "is_you": u["id"] == user_id
        })
    return result

@app.delete("/account")
def delete_account(user_id: int = Depends(get_current_user)):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM campus_status WHERE user_id = %s", (user_id,))
    cur.execute("DELETE FROM sessions WHERE user_id = %s", (user_id,))
    cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
    conn.commit()
    cur.close()
    conn.close()
    return {"message": "Account deleted."}

# Run with: uvicorn main:app --reload
