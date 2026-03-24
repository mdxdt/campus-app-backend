from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional
from contextlib import asynccontextmanager
from apscheduler.schedulers.background import BackgroundScheduler
import psycopg2
import psycopg2.extras
import hashlib
import secrets
import time
import os
from datetime import datetime

# ---------- DATABASE ----------

def get_db():
    url = os.environ["DATABASE_URL"]
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql://", 1)
    return psycopg2.connect(url, cursor_factory=psycopg2.extras.RealDictCursor)

def init_db():
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
            updated_at DOUBLE PRECISION NOT NULL,
            schedule_managed BOOLEAN NOT NULL DEFAULT FALSE
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS schedule (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL,
            day_of_week INTEGER NOT NULL,
            start_time TEXT NOT NULL,
            end_time TEXT NOT NULL,
            label TEXT DEFAULT '',
            is_recurring BOOLEAN NOT NULL DEFAULT TRUE,
            specific_date TEXT DEFAULT NULL
        )
    """)
    conn.commit()
    # Safe migrations for existing databases
    for sql in [
        "ALTER TABLE schedule ADD COLUMN IF NOT EXISTS is_recurring BOOLEAN NOT NULL DEFAULT TRUE",
        "ALTER TABLE schedule ADD COLUMN IF NOT EXISTS specific_date TEXT DEFAULT NULL",
        "ALTER TABLE campus_status ADD COLUMN IF NOT EXISTS schedule_managed BOOLEAN NOT NULL DEFAULT FALSE",
    ]:
        try:
            cur.execute(sql)
            conn.commit()
        except Exception:
            conn.rollback()
    cur.close()
    conn.close()

# ---------- SCHEDULER LOGIC ----------

def run_schedule_tick():
    """
    Runs every minute. For every user:
    - If they have a schedule slot active RIGHT NOW → set ON, expiry = slot end time
    - If they were schedule-managed and no slot is active → set OFF
    This also handles expiry correctly by writing it from the schedule,
    not relying on the client to notice.
    """
    now = datetime.utcnow()
    # day_of_week: Python's weekday() is 0=Monday which matches our schema
    today_dow = now.weekday()
    today_str = now.strftime("%Y-%m-%d")
    current_time = now.strftime("%H:%M")
    unix_now = time.time()

    try:
        conn = get_db()
        cur = conn.cursor()

        # Get all users
        cur.execute("SELECT id FROM users")
        users = cur.fetchall()

        for user in users:
            uid = user["id"]

            # Find any schedule slot that is active for this user right now
            cur.execute("""
                SELECT start_time, end_time, is_recurring, specific_date
                FROM schedule
                WHERE user_id = %s
                  AND day_of_week = %s
                  AND start_time <= %s
                  AND end_time > %s
            """, (uid, today_dow, current_time, current_time))
            slots = cur.fetchall()

            active_slot = None
            for slot in slots:
                if slot["is_recurring"] or slot["specific_date"] == today_str:
                    active_slot = slot
                    break

            if active_slot:
                # Calculate exact Unix timestamp for end of this slot today (UTC)
                end_h, end_m = map(int, active_slot["end_time"].split(":"))
                end_dt = now.replace(hour=end_h, minute=end_m, second=0, microsecond=0)
                expires_at = end_dt.timestamp()

                cur.execute("""
                    INSERT INTO campus_status (user_id, is_on_campus, expires_at, updated_at, schedule_managed)
                    VALUES (%s, TRUE, %s, %s, TRUE)
                    ON CONFLICT (user_id) DO UPDATE SET
                        is_on_campus = TRUE,
                        expires_at = EXCLUDED.expires_at,
                        updated_at = EXCLUDED.updated_at,
                        schedule_managed = TRUE
                    WHERE campus_status.schedule_managed = TRUE
                       OR campus_status.is_on_campus = FALSE
                """, (uid, expires_at, unix_now))
            else:
                # No active slot — if the scheduler was managing this user, turn them off
                cur.execute("""
                    UPDATE campus_status
                    SET is_on_campus = FALSE, expires_at = NULL, updated_at = %s, schedule_managed = FALSE
                    WHERE user_id = %s
                      AND schedule_managed = TRUE
                      AND is_on_campus = TRUE
                """, (unix_now, uid))

                # Also expire anyone whose manual timer has run out
                cur.execute("""
                    UPDATE campus_status
                    SET is_on_campus = FALSE, expires_at = NULL, updated_at = %s
                    WHERE user_id = %s
                      AND is_on_campus = TRUE
                      AND expires_at IS NOT NULL
                      AND expires_at <= %s
                """, (unix_now, uid, unix_now))

        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f"[scheduler] error: {e}")

# ---------- APP STARTUP / SHUTDOWN ----------

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    scheduler = BackgroundScheduler()
    # Run every minute, starting immediately
    scheduler.add_job(run_schedule_tick, "interval", minutes=1, next_run_time=datetime.now())
    scheduler.start()
    print("[scheduler] started — checking schedules every minute")
    yield
    scheduler.shutdown()
    print("[scheduler] stopped")

app = FastAPI(title="Campus App", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()

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

class ScheduleEntry(BaseModel):
    day_of_week: int
    start_time: str
    end_time: str
    label: Optional[str] = ""
    is_recurring: bool = True
    specific_date: Optional[str] = None

# ---------- AUTH ROUTES ----------

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

@app.delete("/account")
def delete_account(user_id: int = Depends(get_current_user)):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM campus_status WHERE user_id = %s", (user_id,))
    cur.execute("DELETE FROM sessions WHERE user_id = %s", (user_id,))
    cur.execute("DELETE FROM schedule WHERE user_id = %s", (user_id,))
    cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
    conn.commit()
    cur.close()
    conn.close()
    return {"message": "Account deleted."}

# ---------- STATUS ROUTES ----------

@app.post("/status")
def update_status(req: StatusUpdateRequest, user_id: int = Depends(get_current_user)):
    now = time.time()
    expires_at = None
    if req.is_on_campus and req.duration_minutes:
        expires_at = now + req.duration_minutes * 60
    conn = get_db()
    cur = conn.cursor()
    # Manual status change: mark schedule_managed=FALSE so scheduler won't override it
    cur.execute("""
        INSERT INTO campus_status (user_id, is_on_campus, expires_at, updated_at, schedule_managed)
        VALUES (%s, %s, %s, %s, FALSE)
        ON CONFLICT (user_id) DO UPDATE SET
            is_on_campus = EXCLUDED.is_on_campus,
            expires_at = EXCLUDED.expires_at,
            updated_at = EXCLUDED.updated_at,
            schedule_managed = FALSE
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
    return {"is_on_campus": bool(row["is_on_campus"]), "expires_at": row["expires_at"]}

@app.get("/users")
def get_all_users(user_id: int = Depends(get_current_user)):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT u.id, u.display_name,
               COALESCE(cs.is_on_campus, FALSE) AS is_on_campus,
               cs.expires_at
        FROM users u
        LEFT JOIN campus_status cs ON u.id = cs.user_id
        ORDER BY cs.is_on_campus DESC NULLS LAST, u.display_name ASC
    """)
    users = cur.fetchall()
    cur.close()
    conn.close()
    return [{
        "id": u["id"],
        "display_name": u["display_name"],
        "is_on_campus": bool(u["is_on_campus"]),
        "expires_at": u["expires_at"],
        "is_you": u["id"] == user_id
    } for u in users]

# ---------- SCHEDULE ROUTES ----------

@app.get("/schedule")
def get_my_schedule(user_id: int = Depends(get_current_user)):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, day_of_week, start_time, end_time, label, is_recurring, specific_date FROM schedule WHERE user_id = %s ORDER BY day_of_week, start_time",
        (user_id,)
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return [dict(r) for r in rows]

@app.post("/schedule")
def add_schedule_entry(entry: ScheduleEntry, user_id: int = Depends(get_current_user)):
    if not entry.is_recurring and not entry.specific_date:
        raise HTTPException(status_code=400, detail="One-off entries require a specific_date.")
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO schedule (user_id, day_of_week, start_time, end_time, label, is_recurring, specific_date)
           VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id""",
        (user_id, entry.day_of_week, entry.start_time, entry.end_time,
         entry.label or "", entry.is_recurring, entry.specific_date)
    )
    new_id = cur.fetchone()["id"]
    conn.commit()
    cur.close()
    conn.close()
    # Immediately run the tick so status updates without waiting up to a minute
    run_schedule_tick()
    return {"id": new_id, "message": "Schedule entry added."}

@app.delete("/schedule/{entry_id}")
def delete_schedule_entry(entry_id: int, user_id: int = Depends(get_current_user)):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "DELETE FROM schedule WHERE id = %s AND user_id = %s RETURNING id",
        (entry_id, user_id)
    )
    deleted = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    if not deleted:
        raise HTTPException(status_code=404, detail="Entry not found.")
    return {"message": "Deleted."}

@app.get("/schedule/all")
def get_all_schedules(user_id: int = Depends(get_current_user)):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT s.id, s.day_of_week, s.start_time, s.end_time, s.label,
               s.is_recurring, s.specific_date, u.display_name, u.id as uid
        FROM schedule s
        JOIN users u ON s.user_id = u.id
        ORDER BY s.day_of_week, s.start_time
    """)
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return [dict(r) for r in rows]

# Run with: uvicorn main:app --reload
