from fastapi import APIRouter, HTTPException, status, Request
from pydantic import BaseModel, EmailStr
from typing import List, Optional
from passlib.context import CryptContext
from backend.db import get_db_connection
from mysql.connector import Error

router = APIRouter()

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")


# ─────────────────────────────────────────────
# PYDANTIC MODELS
# ─────────────────────────────────────────────

class UserRegister(BaseModel):
    username: str
    email: EmailStr
    password: str
    full_name: str = ""
    phone: str = ""
    organization: str = ""
    role: str = "Analyst"


class UserLogin(BaseModel):
    username: str
    password: str


class ApproveBody(BaseModel):
    notes: str = ""
    admin_username: str = "admin"


class RejectBody(BaseModel):
    reason: str = ""
    admin_username: str = "admin"


class BulkActionBody(BaseModel):
    user_ids: List[int]
    action: str          # 'approve' | 'reject'
    notes: str = ""
    admin_username: str = "admin"


class RoleUpdateBody(BaseModel):
    role: str
    admin_username: str = "admin"


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def get_password_hash(password):
    return pwd_context.hash(password)


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def log_audit(cursor, admin_username: str, action: str,
              target_user_id: int = None, target_username: str = None,
              notes: str = ""):
    try:
        cursor.execute(
            """INSERT INTO audit_log
               (admin_username, action, target_user_id, target_username, notes)
               VALUES (%s, %s, %s, %s, %s)""",
            (admin_username, action, target_user_id, target_username, notes or "")
        )
    except Exception as e:
        print(f"Audit log error: {e}")


# ─────────────────────────────────────────────
# AUTH ENDPOINTS
# ─────────────────────────────────────────────

@router.post("/register", status_code=status.HTTP_201_CREATED)
def register(user: UserRegister):
    conn = get_db_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection failed")

    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            "SELECT * FROM users WHERE username = %s OR email = %s",
            (user.username, user.email)
        )
        if cursor.fetchone():
            raise HTTPException(status_code=400, detail="Username or Email already registered")

        hashed_password = get_password_hash(user.password)
        cursor.execute(
            """INSERT INTO users
               (username, email, password_hash, full_name, phone, organization, role, status)
               VALUES (%s, %s, %s, %s, %s, %s, %s, 'pending')""",
            (user.username, user.email, hashed_password,
             user.full_name, user.phone, user.organization, user.role)
        )
        conn.commit()
        return {"message": "Registration successful! Awaiting admin approval."}

    except Error as e:
        conn.rollback()
        print(f"Database error: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")
    finally:
        cursor.close()
        conn.close()


@router.post("/login")
def login(user: UserLogin):
    conn = get_db_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection failed")

    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            "SELECT * FROM users WHERE username = %s OR email = %s",
            (user.username, user.username)
        )
        db_user = cursor.fetchone()

        if not db_user or not verify_password(user.password, db_user["password_hash"]):
            raise HTTPException(status_code=401, detail="Invalid credentials")

        st = db_user.get("status", "pending")
        if st == "pending":
            raise HTTPException(status_code=403, detail="Your account is awaiting admin approval.")
        if st == "rejected":
            raise HTTPException(status_code=403, detail="Your account has been rejected by the admin.")
        if st == "suspended":
            raise HTTPException(status_code=403, detail="Your account has been suspended. Contact admin.")

        # Update last_login (non-critical – skip if column missing)
        try:
            cursor.execute("UPDATE users SET last_login = NOW() WHERE id = %s", (db_user["id"],))
            conn.commit()
        except Exception:
            pass

        return {
            "message": "Login successful",
            "user": {
                "id": db_user["id"],
                "username": db_user["username"],
                "email": db_user["email"],
                "full_name": db_user.get("full_name", ""),
                "organization": db_user.get("organization", ""),
                "role": db_user.get("role", "Analyst"),
                "status": st,
            }
        }

    except Error as e:
        print(f"Database error: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")
    finally:
        cursor.close()
        conn.close()


# ─────────────────────────────────────────────
# ADMIN ENDPOINTS
# ─────────────────────────────────────────────

@router.get("/admin/users")
def get_all_users():
    conn = get_db_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection failed")

    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            """SELECT id, username, email, full_name, phone, organization,
                      role, status, reject_reason, last_login, created_at
               FROM users ORDER BY created_at DESC"""
        )
        users = cursor.fetchall()
        for u in users:
            for field in ("created_at", "last_login"):
                if u.get(field):
                    u[field] = str(u[field])
        return users
    except Error as e:
        raise HTTPException(status_code=500, detail="Internal Server Error")
    finally:
        cursor.close()
        conn.close()


@router.post("/admin/approve/{user_id}")
def approve_user(user_id: int, body: ApproveBody = ApproveBody()):
    conn = get_db_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection failed")

    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT username FROM users WHERE id = %s", (user_id,))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User not found")

        cursor.execute(
            "UPDATE users SET status = 'approved', reject_reason = NULL WHERE id = %s",
            (user_id,)
        )
        log_audit(cursor, body.admin_username, "APPROVED",
                  user_id, row["username"], body.notes)
        conn.commit()
        return {"message": "User approved successfully"}
    except Error as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail="Internal Server Error")
    finally:
        cursor.close()
        conn.close()


@router.post("/admin/reject/{user_id}")
def reject_user(user_id: int, body: RejectBody = RejectBody()):
    conn = get_db_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection failed")

    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT username FROM users WHERE id = %s", (user_id,))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User not found")

        cursor.execute(
            "UPDATE users SET status = 'rejected', reject_reason = %s WHERE id = %s",
            (body.reason, user_id)
        )
        log_audit(cursor, body.admin_username, "REJECTED",
                  user_id, row["username"], body.reason)
        conn.commit()
        return {"message": "User rejected successfully"}
    except Error as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail="Internal Server Error")
    finally:
        cursor.close()
        conn.close()


@router.post("/admin/bulk-action")
def bulk_action(body: BulkActionBody):
    if body.action not in ("approve", "reject"):
        raise HTTPException(status_code=400, detail="Action must be 'approve' or 'reject'")

    conn = get_db_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection failed")

    cursor = conn.cursor(dictionary=True)
    try:
        new_status = "approved" if body.action == "approve" else "rejected"
        success = 0
        for uid in body.user_ids:
            cursor.execute("SELECT username FROM users WHERE id = %s", (uid,))
            row = cursor.fetchone()
            if row:
                cursor.execute(
                    "UPDATE users SET status = %s, reject_reason = %s WHERE id = %s",
                    (new_status, body.notes if body.action == "reject" else None, uid)
                )
                log_audit(cursor, body.admin_username,
                          f"BULK_{body.action.upper()}", uid, row["username"], body.notes)
                success += 1
        conn.commit()
        return {"message": f"{success} users {new_status} successfully."}
    except Error as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail="Internal Server Error")
    finally:
        cursor.close()
        conn.close()


@router.post("/admin/update-role/{user_id}")
def update_role(user_id: int, body: RoleUpdateBody):
    conn = get_db_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection failed")

    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT username FROM users WHERE id = %s", (user_id,))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User not found")

        cursor.execute("UPDATE users SET role = %s WHERE id = %s", (body.role, user_id))
        log_audit(cursor, body.admin_username, f"ROLE_CHANGED → {body.role}",
                  user_id, row["username"])
        conn.commit()
        return {"message": f"Role updated to {body.role}"}
    except Error as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail="Internal Server Error")
    finally:
        cursor.close()
        conn.close()


@router.post("/admin/suspend/{user_id}")
def suspend_user(user_id: int, body: ApproveBody = ApproveBody()):
    conn = get_db_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection failed")

    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT username FROM users WHERE id = %s", (user_id,))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User not found")

        cursor.execute("UPDATE users SET status = 'suspended' WHERE id = %s", (user_id,))
        log_audit(cursor, body.admin_username, "SUSPENDED", user_id, row["username"], body.notes)
        conn.commit()
        return {"message": "User suspended"}
    except Error as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail="Internal Server Error")
    finally:
        cursor.close()
        conn.close()


@router.post("/admin/reactivate/{user_id}")
def reactivate_user(user_id: int, body: ApproveBody = ApproveBody()):
    conn = get_db_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection failed")

    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT username FROM users WHERE id = %s", (user_id,))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User not found")

        cursor.execute("UPDATE users SET status = 'approved' WHERE id = %s", (user_id,))
        log_audit(cursor, body.admin_username, "REACTIVATED", user_id, row["username"])
        conn.commit()
        return {"message": "User reactivated"}
    except Error as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail="Internal Server Error")
    finally:
        cursor.close()
        conn.close()


@router.get("/admin/audit-log")
def get_audit_log():
    conn = get_db_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection failed")

    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            "SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 200"
        )
        logs = cursor.fetchall()
        for log in logs:
            if log.get("created_at"):
                log["created_at"] = str(log["created_at"])
        return logs
    except Error as e:
        raise HTTPException(status_code=500, detail="Internal Server Error")
    finally:
        cursor.close()
        conn.close()


# ─────────────────────────────────────────────
# USER ACTIVITY TRACKING
# ─────────────────────────────────────────────

class ActivityBody(BaseModel):
    username: str
    user_id: Optional[int] = None
    action: str
    page: str = ""
    details: str = ""


@router.post("/activity")
def log_user_activity(body: ActivityBody):
    """Receives activity events from the frontend and stores them."""
    conn = get_db_connection()
    if not conn:
        return {"ok": False}   # Non-critical – never crash the app

    cursor = conn.cursor()
    try:
        cursor.execute(
            """INSERT INTO user_activity (username, user_id, action, page, details)
               VALUES (%s, %s, %s, %s, %s)""",
            (body.username, body.user_id, body.action, body.page, body.details)
        )
        conn.commit()
        return {"ok": True}
    except Exception:
        return {"ok": False}
    finally:
        cursor.close()
        conn.close()


@router.get("/admin/user-activity")
def get_user_activity():
    """Admin: fetch all user activity logs."""
    conn = get_db_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection failed")

    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            "SELECT * FROM user_activity ORDER BY created_at DESC LIMIT 500"
        )
        rows = cursor.fetchall()
        for r in rows:
            if r.get("created_at"):
                r["created_at"] = str(r["created_at"])
        return rows
    except Error as e:
        raise HTTPException(status_code=500, detail="Internal Server Error")
    finally:
        cursor.close()
        conn.close()

