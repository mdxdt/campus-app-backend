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
import pytz

APP_TZ = pytz.timezone("Australia/Melbourne")

def now_melbourne():
    return datetime.now(APP_TZ)

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
            schedule_managed BOOLEAN NOT NULL DEFAULT FALSE,
            manual_override_off BOOLEAN NOT NULL DEFAULT FALSE
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
    cur.execute("""
        CREATE TABLE IF NOT EXISTS friendships (
            id SERIAL PRIMARY KEY,
            requester_id INTEGER NOT NULL,
            addressee_id INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at DOUBLE PRECISION NOT NULL,
            UNIQUE(requester_id, addressee_id)
        )
    """)
    conn.commit()
    # Safe migrations
    for sql in [
        "ALTER TABLE schedule ADD COLUMN IF NOT EXISTS is_recurring BOOLEAN NOT NULL DEFAULT TRUE",
        "ALTER TABLE schedule ADD COLUMN IF NOT EXISTS specific_date TEXT DEFAULT NULL",
        "ALTER TABLE campus_status ADD COLUMN IF NOT EXISTS schedule_managed BOOLEAN NOT NULL DEFAULT FALSE",
        "ALTER TABLE campus_status ADD COLUMN IF NOT EXISTS manual_override_off BOOLEAN NOT NULL DEFAULT FALSE",
    ]:
        try:
            cur.execute(sql)
            conn.commit()
        except Exception:
            conn.rollback()
    cur.close()
    conn.close()

# ---------- SCHEDULER ----------

CAMPUS_TIMEOUT_SECONDS = 24 * 60 * 60  # 24 hour hard cap

def run_schedule_tick():
    """
    Runs every minute in Melbourne time.
    Override logic:
    - manual_override_off=TRUE means user manually went OFF during a scheduled slot.
      Scheduler will NOT turn them back on until the slot ends, then clears the flag.
    - schedule_managed=FALSE + is_on_campus=TRUE means user manually turned ON outside a slot.
      Scheduler will NOT turn them off — unless a NEW scheduled slot begins (takes control back).
    - schedule_managed=TRUE means scheduler is in control; normal on/off applies.
    """
    now = now_melbourne()
    today_dow = now.weekday()
    today_str = now.strftime("%Y-%m-%d")
    current_time = now.strftime("%H:%M")
    unix_now = time.time()

    print(f"[scheduler] tick — Melbourne: {now.strftime('%A %H:%M')} (dow={today_dow})")

    try:
        conn = get_db()
        cur = conn.cursor()

        # Step 1 — expire manual timers
        cur.execute("""
            UPDATE campus_status
            SET is_on_campus = FALSE, expires_at = NULL, updated_at = %s, schedule_managed = FALSE
            WHERE is_on_campus = TRUE
              AND schedule_managed = FALSE
              AND manual_override_off = FALSE
              AND expires_at IS NOT NULL
              AND expires_at <= %s
        """, (unix_now, unix_now))

        # Step 2 — process each user
        cur.execute("SELECT id FROM users")
        users = cur.fetchall()

        for user in users:
            uid = user["id"]

            # Find active slot right now
            cur.execute("""
                SELECT start_time, end_time, is_recurring, specific_date
                FROM schedule
                WHERE user_id = %s AND day_of_week = %s
                  AND start_time <= %s AND end_time > %s
            """, (uid, today_dow, current_time, current_time))
            slots = cur.fetchall()
            active_slot = next(
                (s for s in slots if s["is_recurring"] or s["specific_date"] == today_str),
                None
            )

            cur.execute(
                "SELECT is_on_campus, schedule_managed, manual_override_off FROM campus_status WHERE user_id = %s",
                (uid,)
            )
            status = cur.fetchone()

            if active_slot:
                end_h, end_m = map(int, active_slot["end_time"].split(":"))
                end_dt = now.replace(hour=end_h, minute=end_m, second=0, microsecond=0)
                expires_at = min(end_dt.timestamp(), unix_now + CAMPUS_TIMEOUT_SECONDS)

                if status and status["manual_override_off"]:
                    # User manually went OFF during this slot — respect it, just keep expiry updated
                    cur.execute("""
                        UPDATE campus_status SET expires_at = %s, updated_at = %s
                        WHERE user_id = %s
                    """, (expires_at, unix_now, uid))

                elif status and not status["is_on_campus"] and not status["schedule_managed"]:
                    # User is OFF with no scheduler control — slot is starting, take control
                    cur.execute("""
                        INSERT INTO campus_status (user_id, is_on_campus, expires_at, updated_at, schedule_managed, manual_override_off)
                        VALUES (%s, TRUE, %s, %s, TRUE, FALSE)
                        ON CONFLICT (user_id) DO UPDATE SET
                            is_on_campus = TRUE, expires_at = EXCLUDED.expires_at,
                            updated_at = EXCLUDED.updated_at, schedule_managed = TRUE,
                            manual_override_off = FALSE
                    """, (uid, expires_at, unix_now))
                    print(f"[scheduler] user {uid} → ON until {active_slot['end_time']}")

                elif status is None:
                    # No status row yet
                    cur.execute("""
                        INSERT INTO campus_status (user_id, is_on_campus, expires_at, updated_at, schedule_managed, manual_override_off)
                        VALUES (%s, TRUE, %s, %s, TRUE, FALSE)
                    """, (uid, expires_at, unix_now))
                    print(f"[scheduler] user {uid} → ON until {active_slot['end_time']}")

                elif status["schedule_managed"]:
                    # Scheduler already in control — keep expiry refreshed
                    cur.execute("""
                        UPDATE campus_status SET is_on_campus = TRUE, expires_at = %s, updated_at = %s
                        WHERE user_id = %s
                    """, (expires_at, unix_now, uid))

                elif not status["schedule_managed"] and status["is_on_campus"]:
                    # User manually turned ON — a scheduled slot is now active, hand control to scheduler
                    # but keep them on (slot takes over management)
                    cur.execute("""
                        UPDATE campus_status SET schedule_managed = TRUE, expires_at = %s, updated_at = %s
                        WHERE user_id = %s
                    """, (expires_at, unix_now, uid))
                    print(f"[scheduler] user {uid} manual ON → now schedule-managed until {active_slot['end_time']}")

            else:
                # No active slot
                if status and status["manual_override_off"]:
                    # Slot has ended — clear the override flag, turn OFF
                    cur.execute("""
                        UPDATE campus_status
                        SET is_on_campus = FALSE, expires_at = NULL, updated_at = %s,
                            schedule_managed = FALSE, manual_override_off = FALSE
                        WHERE user_id = %s
                    """, (unix_now, uid))
                    print(f"[scheduler] user {uid} → OFF (override cleared, slot ended)")

                elif status and status["schedule_managed"] and status["is_on_campus"]:
                    # Scheduler was managing — slot ended, turn off
                    cur.execute("""
                        UPDATE campus_status
                        SET is_on_campus = FALSE, expires_at = NULL, updated_at = %s,
                            schedule_managed = FALSE
                        WHERE user_id = %s AND schedule_managed = TRUE
                    """, (unix_now, uid))
                    print(f"[scheduler] user {uid} → OFF (slot ended)")

        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f"[scheduler] error: {e}")

# ---------- APP STARTUP ----------

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    scheduler = BackgroundScheduler()
    scheduler.add_job(run_schedule_tick, "interval", minutes=1, next_run_time=now_melbourne())
    scheduler.start()
    print("[scheduler] started")
    yield
    scheduler.shutdown()

app = FastAPI(title="Campus App", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
security = HTTPBearer()

# ---------- HELPERS ----------

def hash_password(p): return hashlib.sha256(p.encode()).hexdigest()

def create_session(user_id):
    token = secrets.token_hex(32)
    conn = get_db(); cur = conn.cursor()
    cur.execute("INSERT INTO sessions (token, user_id, created_at) VALUES (%s, %s, %s)", (token, user_id, time.time()))
    conn.commit(); cur.close(); conn.close()
    return token

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT user_id FROM sessions WHERE token = %s", (credentials.credentials,))
    row = cur.fetchone(); cur.close(); conn.close()
    if not row: raise HTTPException(status_code=401, detail="Invalid or expired token. Please log in again.")
    return row["user_id"]

def friendship_status(cur, me, other):
    cur.execute("""
        SELECT status, requester_id FROM friendships
        WHERE (requester_id = %s AND addressee_id = %s)
           OR (requester_id = %s AND addressee_id = %s)
    """, (me, other, other, me))
    return cur.fetchone()

# ---------- MODELS ----------

class RegisterRequest(BaseModel):
    username: str; password: str; display_name: str

class LoginRequest(BaseModel):
    username: str; password: str

class StatusUpdateRequest(BaseModel):
    is_on_campus: bool
    duration_minutes: Optional[int] = None

class ScheduleEntry(BaseModel):
    day_of_week: int; start_time: str; end_time: str
    label: Optional[str] = ""
    is_recurring: bool = True
    specific_date: Optional[str] = None

# ---------- AUTH ----------

@app.post("/register")
def register(req: RegisterRequest):
    if len(req.username) < 3: raise HTTPException(400, "Username must be at least 3 characters.")
    if len(req.password) < 6: raise HTTPException(400, "Password must be at least 6 characters.")
    conn = get_db(); cur = conn.cursor()
    try:
        cur.execute("INSERT INTO users (username, password_hash, display_name) VALUES (%s, %s, %s)",
                    (req.username.lower(), hash_password(req.password), req.display_name))
        conn.commit()
    except psycopg2.errors.UniqueViolation:
        conn.rollback(); raise HTTPException(400, "That username is already taken.")
    finally: cur.close(); conn.close()
    return {"message": "Account created!"}

@app.post("/login")
def login(req: LoginRequest):
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT id, display_name FROM users WHERE username = %s AND password_hash = %s",
                (req.username.lower(), hash_password(req.password)))
    user = cur.fetchone(); cur.close(); conn.close()
    if not user: raise HTTPException(401, "Incorrect username or password.")
    return {"token": create_session(user["id"]), "display_name": user["display_name"], "user_id": user["id"]}

@app.post("/logout")
def logout(user_id: int = Depends(get_current_user), credentials: HTTPAuthorizationCredentials = Depends(security)):
    conn = get_db(); cur = conn.cursor()
    cur.execute("DELETE FROM sessions WHERE token = %s", (credentials.credentials,))
    conn.commit(); cur.close(); conn.close()
    return {"message": "Logged out."}

@app.delete("/account")
def delete_account(user_id: int = Depends(get_current_user)):
    conn = get_db(); cur = conn.cursor()
    for tbl in ["campus_status", "sessions", "schedule"]:
        cur.execute(f"DELETE FROM {tbl} WHERE user_id = %s", (user_id,))
    cur.execute("DELETE FROM friendships WHERE requester_id = %s OR addressee_id = %s", (user_id, user_id))
    cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
    conn.commit(); cur.close(); conn.close()
    return {"message": "Account deleted."}

# ---------- STATUS ----------

@app.post("/status")
def update_status(req: StatusUpdateRequest, user_id: int = Depends(get_current_user)):
    now_unix = time.time()

    # Check if currently in a scheduled slot (Melbourne time)
    now = now_melbourne()
    today_dow = now.weekday()
    today_str = now.strftime("%Y-%m-%d")
    current_time = now.strftime("%H:%M")

    conn = get_db(); cur = conn.cursor()
    cur.execute("""
        SELECT start_time, end_time, is_recurring, specific_date FROM schedule
        WHERE user_id = %s AND day_of_week = %s AND start_time <= %s AND end_time > %s
    """, (user_id, today_dow, current_time, current_time))
    slots = cur.fetchall()
    active_slot = next((s for s in slots if s["is_recurring"] or s["specific_date"] == today_str), None)
    in_scheduled_slot = active_slot is not None

    if not req.is_on_campus and in_scheduled_slot:
        # Manual OFF during scheduled time — set override flag, scheduler won't re-enable
        cur.execute("""
            INSERT INTO campus_status (user_id, is_on_campus, expires_at, updated_at, schedule_managed, manual_override_off)
            VALUES (%s, FALSE, NULL, %s, FALSE, TRUE)
            ON CONFLICT (user_id) DO UPDATE SET
                is_on_campus = FALSE, expires_at = NULL,
                updated_at = EXCLUDED.updated_at, schedule_managed = FALSE, manual_override_off = TRUE
        """, (user_id, now_unix))

    elif req.is_on_campus and in_scheduled_slot:
        # Manual ON during scheduled time — clear override, hand back to scheduler
        # Use the slot's end time as expiry (no new schedule entry created)
        end_h, end_m = map(int, active_slot["end_time"].split(":"))
        end_dt = now.replace(hour=end_h, minute=end_m, second=0, microsecond=0)
        expires_at = min(end_dt.timestamp(), now_unix + CAMPUS_TIMEOUT_SECONDS)
        cur.execute("""
            INSERT INTO campus_status (user_id, is_on_campus, expires_at, updated_at, schedule_managed, manual_override_off)
            VALUES (%s, TRUE, %s, %s, TRUE, FALSE)
            ON CONFLICT (user_id) DO UPDATE SET
                is_on_campus = TRUE, expires_at = EXCLUDED.expires_at,
                updated_at = EXCLUDED.updated_at, schedule_managed = TRUE, manual_override_off = FALSE
        """, (user_id, expires_at, now_unix))

    elif req.is_on_campus:
        # Manual ON outside scheduled time — cap at 24 hours
        expires_at = now_unix + CAMPUS_TIMEOUT_SECONDS
        if req.duration_minutes:
            expires_at = min(now_unix + req.duration_minutes * 60, now_unix + CAMPUS_TIMEOUT_SECONDS)
        cur.execute("""
            INSERT INTO campus_status (user_id, is_on_campus, expires_at, updated_at, schedule_managed, manual_override_off)
            VALUES (%s, TRUE, %s, %s, FALSE, FALSE)
            ON CONFLICT (user_id) DO UPDATE SET
                is_on_campus = TRUE, expires_at = EXCLUDED.expires_at,
                updated_at = EXCLUDED.updated_at, schedule_managed = FALSE, manual_override_off = FALSE
        """, (user_id, expires_at, now_unix))

    else:
        # Manual OFF outside scheduled time
        cur.execute("""
            INSERT INTO campus_status (user_id, is_on_campus, expires_at, updated_at, schedule_managed, manual_override_off)
            VALUES (%s, FALSE, NULL, %s, FALSE, FALSE)
            ON CONFLICT (user_id) DO UPDATE SET
                is_on_campus = FALSE, expires_at = NULL,
                updated_at = EXCLUDED.updated_at, schedule_managed = FALSE, manual_override_off = FALSE
        """, (user_id, now_unix))

    conn.commit(); cur.close(); conn.close()
    return {"message": "Status updated."}

@app.get("/status/me")
def get_my_status(user_id: int = Depends(get_current_user)):
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT is_on_campus, expires_at FROM campus_status WHERE user_id = %s", (user_id,))
    row = cur.fetchone(); cur.close(); conn.close()
    if not row: return {"is_on_campus": False, "expires_at": None}
    return {"is_on_campus": bool(row["is_on_campus"]), "expires_at": row["expires_at"]}

@app.get("/users")
def get_all_users(user_id: int = Depends(get_current_user)):
    conn = get_db(); cur = conn.cursor()
    # Get friend IDs
    cur.execute("""
        SELECT CASE WHEN requester_id = %s THEN addressee_id ELSE requester_id END as friend_id
        FROM friendships WHERE status = 'accepted' AND (requester_id = %s OR addressee_id = %s)
    """, (user_id, user_id, user_id))
    friend_ids = {r["friend_id"] for r in cur.fetchall()}

    cur.execute("""
        SELECT u.id, u.display_name,
               COALESCE(cs.is_on_campus, FALSE) AS is_on_campus,
               cs.expires_at
        FROM users u
        LEFT JOIN campus_status cs ON u.id = cs.user_id
        ORDER BY cs.is_on_campus DESC NULLS LAST, u.display_name ASC
    """)
    users = cur.fetchall(); cur.close(); conn.close()

    result = []
    for u in users:
        is_friend = u["id"] in friend_ids
        is_you = u["id"] == user_id
        can_see_status = is_you or is_friend
        result.append({
            "id": u["id"],
            "display_name": u["display_name"],
            "is_on_campus": bool(u["is_on_campus"]) if can_see_status else None,
            "expires_at": u["expires_at"] if can_see_status else None,
            "is_you": is_you,
            "is_friend": is_friend,
        })
    return result

# ---------- SCHEDULE ----------

@app.get("/schedule")
def get_my_schedule(user_id: int = Depends(get_current_user)):
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT id, day_of_week, start_time, end_time, label, is_recurring, specific_date FROM schedule WHERE user_id = %s ORDER BY day_of_week, start_time", (user_id,))
    rows = cur.fetchall(); cur.close(); conn.close()
    return [dict(r) for r in rows]

@app.post("/schedule")
def add_schedule_entry(entry: ScheduleEntry, user_id: int = Depends(get_current_user)):
    if not entry.is_recurring and not entry.specific_date:
        raise HTTPException(400, "One-off entries require a specific_date.")
    conn = get_db(); cur = conn.cursor()
    cur.execute(
        "INSERT INTO schedule (user_id, day_of_week, start_time, end_time, label, is_recurring, specific_date) VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING id",
        (user_id, entry.day_of_week, entry.start_time, entry.end_time, entry.label or "", entry.is_recurring, entry.specific_date)
    )
    new_id = cur.fetchone()["id"]
    conn.commit(); cur.close(); conn.close()
    run_schedule_tick()
    return {"id": new_id, "message": "Schedule entry added."}

@app.delete("/schedule/{entry_id}")
def delete_schedule_entry(entry_id: int, user_id: int = Depends(get_current_user)):
    conn = get_db(); cur = conn.cursor()
    cur.execute("DELETE FROM schedule WHERE id = %s AND user_id = %s RETURNING id", (entry_id, user_id))
    deleted = cur.fetchone(); conn.commit(); cur.close(); conn.close()
    if not deleted: raise HTTPException(404, "Entry not found.")
    return {"message": "Deleted."}

# ---------- FRIENDS ----------

@app.get("/friends")
def get_friends(user_id: int = Depends(get_current_user)):
    """Get accepted friends with their campus status, and pending requests."""
    conn = get_db(); cur = conn.cursor()
    cur.execute("""
        SELECT f.id, f.status, f.requester_id, f.addressee_id,
               u.id as other_id, u.display_name,
               COALESCE(cs.is_on_campus, FALSE) as is_on_campus, cs.expires_at,
               (f.requester_id = %s) as i_sent_this
        FROM friendships f
        JOIN users u ON u.id = CASE WHEN f.requester_id = %s THEN f.addressee_id ELSE f.requester_id END
        LEFT JOIN campus_status cs ON cs.user_id = u.id
        WHERE f.requester_id = %s OR f.addressee_id = %s
        ORDER BY f.status, u.display_name
    """, (user_id, user_id, user_id, user_id))
    rows = cur.fetchall(); cur.close(); conn.close()
    return [dict(r) for r in rows]

@app.post("/friends/request/{other_id}")
def send_friend_request(other_id: int, user_id: int = Depends(get_current_user)):
    if other_id == user_id: raise HTTPException(400, "You can't add yourself.")
    conn = get_db(); cur = conn.cursor()
    # Check user exists
    cur.execute("SELECT id FROM users WHERE id = %s", (other_id,))
    if not cur.fetchone(): raise HTTPException(404, "User not found.")
    try:
        cur.execute(
            "INSERT INTO friendships (requester_id, addressee_id, status, created_at) VALUES (%s, %s, 'pending', %s)",
            (user_id, other_id, time.time())
        )
        conn.commit()
    except psycopg2.errors.UniqueViolation:
        conn.rollback(); raise HTTPException(400, "Friend request already exists.")
    finally: cur.close(); conn.close()
    return {"message": "Friend request sent."}

@app.post("/friends/accept/{friendship_id}")
def accept_friend_request(friendship_id: int, user_id: int = Depends(get_current_user)):
    conn = get_db(); cur = conn.cursor()
    cur.execute(
        "UPDATE friendships SET status = 'accepted' WHERE id = %s AND addressee_id = %s RETURNING id",
        (friendship_id, user_id)
    )
    if not cur.fetchone(): raise HTTPException(404, "Request not found or not addressed to you.")
    conn.commit(); cur.close(); conn.close()
    return {"message": "Friend request accepted."}

@app.delete("/friends/{friendship_id}")
def remove_friend(friendship_id: int, user_id: int = Depends(get_current_user)):
    conn = get_db(); cur = conn.cursor()
    cur.execute(
        "DELETE FROM friendships WHERE id = %s AND (requester_id = %s OR addressee_id = %s) RETURNING id",
        (friendship_id, user_id, user_id)
    )
    if not cur.fetchone(): raise HTTPException(404, "Friendship not found.")
    conn.commit(); cur.close(); conn.close()
    return {"message": "Removed."}

@app.get("/users/search")
def search_users(q: str = "", user_id: int = Depends(get_current_user)):
    """Search users by display name or username. Returns all users if q is empty."""
    conn = get_db(); cur = conn.cursor()
    where_clause = "WHERE u.id != %s" if not q.strip() else "WHERE u.id != %s AND (LOWER(u.display_name) LIKE LOWER(%s) OR LOWER(u.username) LIKE LOWER(%s))"
    params = (user_id,) if not q.strip() else (user_id, f"%{q}%", f"%{q}%")
    cur.execute(f"""
        SELECT u.id, u.display_name, u.username,
               f.id as friendship_id, f.status,
               f.requester_id, f.addressee_id
        FROM users u
        LEFT JOIN friendships f ON (
            (f.requester_id = %s AND f.addressee_id = u.id) OR
            (f.addressee_id = %s AND f.requester_id = u.id)
        )
        {where_clause}
        ORDER BY u.display_name ASC
        LIMIT 50
    """, (user_id, user_id) + params)
    rows = cur.fetchall(); cur.close(); conn.close()
    return [dict(r) for r in rows]

# Run with: uvicorn main:app --reload
