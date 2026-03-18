from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional
import sqlite3
import hashlib
import secrets
import time
from datetime import datetime, timedelta

app = FastAPI(title="Campus App")

# Allow the frontend to talk to the backend
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
    """Connect to the SQLite database (creates the file if it doesn't exist)."""
    conn = sqlite3.connect("campus.db")
    conn.row_factory = sqlite3.Row  # lets us access columns by name
    return conn

def init_db():
    """Create tables if they don't exist yet."""
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            display_name TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at REAL NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS campus_status (
            user_id INTEGER PRIMARY KEY,
            is_on_campus INTEGER NOT NULL DEFAULT 0,
            expires_at REAL,
            updated_at REAL NOT NULL
        )
    """)
    conn.commit()
    conn.close()

init_db()

# ---------- HELPERS ----------

def hash_password(password: str) -> str:
    """Simple SHA-256 hash. In production use bcrypt."""
    return hashlib.sha256(password.encode()).hexdigest()

def create_session(user_id: int) -> str:
    """Create a random session token and store it."""
    token = secrets.token_hex(32)
    conn = get_db()
    conn.execute(
        "INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)",
        (token, user_id, time.time())
    )
    conn.commit()
    conn.close()
    return token

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Validate the token and return the user_id."""
    token = credentials.credentials
    conn = get_db()
    row = conn.execute(
        "SELECT user_id FROM sessions WHERE token = ?", (token,)
    ).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=401, detail="Invalid or expired token. Please log in again.")
    return row["user_id"]

# ---------- REQUEST/RESPONSE MODELS ----------

class RegisterRequest(BaseModel):
    username: str
    password: str
    display_name: str

class LoginRequest(BaseModel):
    username: str
    password: str

class StatusUpdateRequest(BaseModel):
    is_on_campus: bool
    duration_minutes: Optional[int] = None  # None means indefinite

# ---------- ROUTES ----------

@app.post("/register")
def register(req: RegisterRequest):
    """Create a new account."""
    if len(req.username) < 3:
        raise HTTPException(status_code=400, detail="Username must be at least 3 characters.")
    if len(req.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters.")
    
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash, display_name) VALUES (?, ?, ?)",
            (req.username.lower(), hash_password(req.password), req.display_name)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="That username is already taken.")
    finally:
        conn.close()
    
    return {"message": "Account created! You can now log in."}

@app.post("/login")
def login(req: LoginRequest):
    """Log in and receive a session token."""
    conn = get_db()
    user = conn.execute(
        "SELECT id, display_name FROM users WHERE username = ? AND password_hash = ?",
        (req.username.lower(), hash_password(req.password))
    ).fetchone()
    conn.close()
    
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password.")
    
    token = create_session(user["id"])
    return {"token": token, "display_name": user["display_name"], "user_id": user["id"]}

@app.post("/logout")
def logout(user_id: int = Depends(get_current_user), credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Delete the session token."""
    conn = get_db()
    conn.execute("DELETE FROM sessions WHERE token = ?", (credentials.credentials,))
    conn.commit()
    conn.close()
    return {"message": "Logged out."}

@app.post("/status")
def update_status(req: StatusUpdateRequest, user_id: int = Depends(get_current_user)):
    """Set whether the current user is on campus, with an optional time limit."""
    now = time.time()
    expires_at = None
    if req.is_on_campus and req.duration_minutes:
        expires_at = now + req.duration_minutes * 60
    
    conn = get_db()
    conn.execute("""
        INSERT INTO campus_status (user_id, is_on_campus, expires_at, updated_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET
            is_on_campus = excluded.is_on_campus,
            expires_at = excluded.expires_at,
            updated_at = excluded.updated_at
    """, (user_id, int(req.is_on_campus), expires_at, now))
    conn.commit()
    conn.close()
    return {"message": "Status updated."}

@app.get("/status/me")
def get_my_status(user_id: int = Depends(get_current_user)):
    """Get the current user's campus status."""
    conn = get_db()
    row = conn.execute(
        "SELECT is_on_campus, expires_at FROM campus_status WHERE user_id = ?", (user_id,)
    ).fetchone()
    conn.close()
    
    if not row:
        return {"is_on_campus": False, "expires_at": None}
    
    # Check if it's expired
    now = time.time()
    if row["expires_at"] and now > row["expires_at"]:
        return {"is_on_campus": False, "expires_at": None}
    
    return {
        "is_on_campus": bool(row["is_on_campus"]),
        "expires_at": row["expires_at"]
    }

@app.get("/users")
def get_all_users(user_id: int = Depends(get_current_user)):
    """Get all users and their campus status."""
    now = time.time()
    conn = get_db()
    
    users = conn.execute("""
        SELECT 
            u.id,
            u.display_name,
            COALESCE(cs.is_on_campus, 0) AS is_on_campus,
            cs.expires_at,
            cs.updated_at
        FROM users u
        LEFT JOIN campus_status cs ON u.id = cs.user_id
        ORDER BY cs.is_on_campus DESC, u.display_name ASC
    """).fetchall()
    conn.close()
    
    result = []
    for u in users:
        # Treat expired statuses as off-campus
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

# Run with: uvicorn main:app --reload
