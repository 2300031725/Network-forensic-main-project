from backend.db import get_db_connection

def list_users():
    conn = get_db_connection()
    if not conn:
        print("Failed to connect to DB.")
        return

    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, username, email, password_hash, created_at FROM users")
    users = cursor.fetchall()
    
    print("\n--- Registered Users ---")
    for user in users:
        print(f"ID: {user['id']}")
        print(f"Username: {user['username']}")
        print(f"Email: {user['email']}")
        print(f"Hash Start: {user['password_hash'][:20]}...")
        print("------------------------")
    
    if not users:
        print("No users found in database.")

    cursor.close()
    conn.close()

if __name__ == "__main__":
    import sys
    # Redirect stdout to a file with utf-8 encoding
    with open("users_list_utf8.txt", "w", encoding="utf-8") as f:
        original_stdout = sys.stdout
        sys.stdout = f
        list_users()
        sys.stdout = original_stdout
    print("Output written to users_list_utf8.txt")
