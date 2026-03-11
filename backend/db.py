import mysql.connector
from mysql.connector import Error
import os
from dotenv import load_dotenv

load_dotenv()

def get_db_connection():
    """Establishes and returns a connection to the MySQL database."""
    try:
        connection = mysql.connector.connect(
            host=os.getenv("DB_HOST", "localhost"),
            user=os.getenv("DB_USER", "root"),
            password=os.getenv("DB_PASSWORD", ""),
            database=os.getenv("DB_NAME", "skillpalavar_db")
        )
        if connection.is_connected():
            return connection
    except Error as e:
        print(f"Error connecting to MySQL: {e}")
        return None

def init_db():
    """Initializes the database tables."""
    try:
        connection = mysql.connector.connect(
            host=os.getenv("DB_HOST", "localhost"),
            user=os.getenv("DB_USER", "root"),
            password=os.getenv("DB_PASSWORD", "")
        )
        if connection.is_connected():
            cursor = connection.cursor()
            db_name = os.getenv("DB_NAME", "skillpalavar_db")
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS {db_name}")
            cursor.close()
            connection.close()

        connection = get_db_connection()
        if connection:
            cursor = connection.cursor()

            # ── Users table ──────────────────────────────────────────────
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id            INT AUTO_INCREMENT PRIMARY KEY,
                username      VARCHAR(50)  NOT NULL UNIQUE,
                email         VARCHAR(100) NOT NULL UNIQUE,
                password_hash VARCHAR(255) NOT NULL,
                full_name     VARCHAR(100) DEFAULT '',
                phone         VARCHAR(20)  DEFAULT '',
                organization  VARCHAR(100) DEFAULT '',
                role          VARCHAR(50)  DEFAULT 'Analyst',
                status        VARCHAR(20)  DEFAULT 'pending',
                reject_reason TEXT         DEFAULT NULL,
                last_login    TIMESTAMP    DEFAULT NULL,
                created_at    TIMESTAMP    DEFAULT CURRENT_TIMESTAMP
            )
            """)

            # ── User Activity table ───────────────────────────────────────
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_activity (
                id         INT AUTO_INCREMENT PRIMARY KEY,
                username   VARCHAR(50)  NOT NULL,
                user_id    INT          DEFAULT NULL,
                action     VARCHAR(150) NOT NULL,
                page       VARCHAR(100) DEFAULT NULL,
                details    TEXT         DEFAULT NULL,
                created_at TIMESTAMP    DEFAULT CURRENT_TIMESTAMP
            )
            """)

            # ── Audit log table ───────────────────────────────────────────
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id               INT AUTO_INCREMENT PRIMARY KEY,
                admin_username   VARCHAR(50)  NOT NULL,
                action           VARCHAR(100) NOT NULL,
                target_user_id   INT          DEFAULT NULL,
                target_username  VARCHAR(50)  DEFAULT NULL,
                notes            TEXT         DEFAULT NULL,
                created_at       TIMESTAMP    DEFAULT CURRENT_TIMESTAMP
            )
            """)

            # ── Backward-compat ALTER statements (skip if column exists) ──
            alter_statements = [
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS full_name     VARCHAR(100) DEFAULT ''",
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS phone         VARCHAR(20)  DEFAULT ''",
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS organization  VARCHAR(100) DEFAULT ''",
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS role          VARCHAR(50)  DEFAULT 'Analyst'",
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS status        VARCHAR(20)  DEFAULT 'pending'",
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS reject_reason TEXT         DEFAULT NULL",
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login    TIMESTAMP    DEFAULT NULL",
                "ALTER TABLE user_activity ADD COLUMN IF NOT EXISTS user_id INT DEFAULT NULL",
            ]
            for stmt in alter_statements:
                try:
                    cursor.execute(stmt)
                except Exception:
                    pass

            cursor.close()
            connection.close()
            print("Database initialised successfully.")
    except Error as e:
        print(f"Error initialising database: {e}")

if __name__ == "__main__":
    init_db()
