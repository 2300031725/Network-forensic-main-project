from backend.db import get_db_connection

def show_users():
    conn = get_db_connection()
    if not conn:
        print("Failed to connect")
        return

    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    
    print(f"Found {len(users)} users:")
    for user in users:
        print(user)
    
    conn.close()

if __name__ == "__main__":
    show_users()
