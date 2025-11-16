"""MySQL users table + salted hashing (no chat storage)."""

import os
import sys
import pymysql
from dotenv import load_dotenv
from app.common.utils import sha256_hex

# Load environment variables
load_dotenv()


def get_db_connection():
    """
    Create and return a MySQL database connection.
    
    Returns:
        pymysql.Connection object
    """
    return pymysql.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=int(os.getenv("DB_PORT", 3306)),
        user=os.getenv("DB_USER", "scuser"),
        password=os.getenv("DB_PASSWORD", "scpass"),
        database=os.getenv("DB_NAME", "securechat"),
        charset='utf8mb4',
        cursorclass=pymysql.cursors.DictCursor
    )


def init_db():
    """
    Initialize the database by creating the users table.
    """
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # Create users table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    email VARCHAR(255) PRIMARY KEY,
                    username VARCHAR(255) UNIQUE NOT NULL,
                    salt VARBINARY(16) NOT NULL,
                    pwd_hash CHAR(64) NOT NULL
                )
            """)
            conn.commit()
            print("✅ Database initialized successfully!")
            print("   Table 'users' created with schema:")
            print("   - email VARCHAR(255) PRIMARY KEY")
            print("   - username VARCHAR(255) UNIQUE")
            print("   - salt VARBINARY(16)")
            print("   - pwd_hash CHAR(64)")
    finally:
        conn.close()


def register_user(email: str, username: str, password: str) -> bool:
    """
    Register a new user with salted password hashing.
    
    Args:
        email: User email (primary key)
        username: Unique username
        password: Plain text password
        
    Returns:
        True if registration successful, False otherwise
    """
    import os as os_module
    
    # Generate random 16-byte salt
    salt = os_module.urandom(16)
    
    # Compute pwd_hash = hex(SHA256(salt || password))
    pwd_hash = sha256_hex(salt + password.encode('utf-8'))
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)",
                (email, username, salt, pwd_hash)
            )
            conn.commit()
            return True
    except pymysql.err.IntegrityError as e:
        # Duplicate email or username
        print(f"Registration failed: {e}")
        return False
    except Exception as e:
        print(f"Database error: {e}")
        return False
    finally:
        conn.close()


def verify_login(email: str, password: str) -> bool:
    """
    Verify user login credentials.
    
    Args:
        email: User email
        password: Plain text password
        
    Returns:
        True if credentials are valid, False otherwise
    """
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT salt, pwd_hash FROM users WHERE email = %s",
                (email,)
            )
            result = cursor.fetchone()
            
            if not result:
                return False
            
            salt = result['salt']
            stored_hash = result['pwd_hash']
            
            # Compute hash with provided password
            computed_hash = sha256_hex(salt + password.encode('utf-8'))
            
            # Compare hashes
            return computed_hash == stored_hash
    except Exception as e:
        print(f"Database error: {e}")
        return False
    finally:
        conn.close()


def get_username(email: str) -> str:
    """
    Get username for a given email.
    
    Args:
        email: User email
        
    Returns:
        Username or None if not found
    """
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT username FROM users WHERE email = %s",
                (email,)
            )
            result = cursor.fetchone()
            return result['username'] if result else None
    finally:
        conn.close()


def main():
    """CLI entry point for database initialization."""
    if len(sys.argv) > 1 and sys.argv[1] == "--init":
        init_db()
    else:
        print("Usage: python -m app.storage.db --init")


if __name__ == "__main__":
    main()
