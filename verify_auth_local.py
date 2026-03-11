import sys
import os
import random
import string
from backend.db import get_db_connection, init_db
from backend.auth import get_password_hash, verify_password

def test_db_connection():
    print("Testing Database Connection...")
    conn = get_db_connection()
    if conn:
        print("✅ Database connection successful.")
        conn.close()
        return True
    else:
        print("❌ Database connection failed. Check .env credentials.")
        return False

def test_init_db():
    print("\nTesting Database Initialization...")
    try:
        init_db()
        print("✅ Database initialization ran without error.")
        return True
    except Exception as e:
        print(f"❌ Database initialization failed: {e}")
        return False

def test_user_creation_and_auth():
    print("\nTesting User Creation and Authentication Logic...")
    conn = get_db_connection()
    if not conn:
        print("❌ Skipping auth test due to DB connection failure.")
        return

    cursor = conn.cursor(dictionary=True)
    
    # Generate random user
    username = "testuser_" + ''.join(random.choices(string.ascii_lowercase, k=5))
    email = username + "@example.com"
    password = "secretpassword"
    
    print(f"Attempting to register user: {username}")
    
    try:
        # 1. Register (Insert directly to test logic)
        hashed_pw = get_password_hash(password)
        cursor.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)",
            (username, email, hashed_pw)
        )
        conn.commit()
        print(f"✅ User {username} inserted successfully.")
        
        # 2. Login (Verify password)
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        
        if user:
            print(f"✅ User found in DB: {user}")  # Show the real data
            if verify_password(password, user['password_hash']):
                 print("✅ Password verification successful.")
            else:
                 print("❌ Password verification failed.")
        else:
             print("❌ User not found after insertion.")
             
        # Cleanup
        cursor.execute("DELETE FROM users WHERE username = %s", (username,))
        conn.commit()
        print("✅ Test user cleaned up.")

    except Exception as e:
        import traceback
        with open("debug_traceback.txt", "w", encoding="utf-8") as f:
            f.write(traceback.format_exc())
        print(f"❌ Auth test failed: {e}")
    finally:
        cursor.close()
        conn.close()

if __name__ == "__main__":
    if test_db_connection():
        if test_init_db():
            test_user_creation_and_auth()
