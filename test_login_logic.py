from backend.auth import login, UserLogin
from fastapi import HTTPException

def test_login(identifier, password):
    print(f"Testing login for: {identifier}")
    try:
        user_data = UserLogin(username=identifier, password=password)
        result = login(user_data)
        print("✅ Login SUCCESS!")
        print(f"User: {result['user']}")
        return True
    except HTTPException as e:
        print(f"❌ Login FAILED: {e.detail}")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

if __name__ == "__main__":
    # Replace these with what you are trying to use
    # I am using a likely password. If you set a specific password, 
    # you can edit this script to test it.
    
    # Since I don't know the user's password, I can't verify it succeeds 100%
    # But I can verify it TRIES the email lookup.
    
    # However, I can try to register a NEW user with a known password and test logging in with EMAIL.
    pass
    
    # BETTER APPROACH:
    # 1. Register a temporary user
    # 2. Try to login with EMAIL
    # 3. Delete user
    
    from backend.auth import register, UserRegister
    import random
    
    rand_id = str(random.randint(1000,9999))
    temp_user = f"debug_user_{rand_id}"
    temp_email = f"debug_{rand_id}@test.com"
    temp_pass = "debugpass123"
    
    print(f"\n--- Creating Temp User: {temp_user} / {temp_email} ---")
    try:
        register(UserRegister(username=temp_user, email=temp_email, password=temp_pass))
        print("✅ Temp user registered.")
    except Exception as e:
        print(f"⚠️ Registration failed (maybe exists?): {e}")

    print(f"\n--- Attempting Login with EMAIL: {temp_email} ---")
    if test_login(temp_email, temp_pass):
        print(">>> Backend Logic for EMAIL Login is WORKING.")
    else:
        print(">>> Backend Logic for EMAIL Login FAILED.")
        
    # Cleanup
    from backend.db import get_db_connection
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE username = %s", (temp_user,))
        conn.commit()
        conn.close()
        print("\n--- Temp user cleaned up ---")
