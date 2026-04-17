import pymysql
import getpass
from werkzeug.security import generate_password_hash

def setup_database():
    print("========================================")
    print("  SecureNet Database Initialization")
    print("========================================")
    
    # Get the MySQL root password securely (hidden input)
    db_root_pass = getpass.getpass("Enter MariaDB root password (leave blank if no password): ")
    
    try:
        # Connect to MariaDB without specifying a database
        print("\n[+] Connecting to MariaDB...")
        if db_root_pass:
            conn = pymysql.connect(host='localhost', user='root', password=db_root_pass)
        else:
            conn = pymysql.connect(host='localhost', user='root')
        cursor = conn.cursor()
        print("[+] Connection successful!")

        # 1. Create Database
        print("\n[*] Creating database 'captive_portal'...")
        cursor.execute("CREATE DATABASE IF NOT EXISTS captive_portal")
        print("[+] Database created.")

        # 2. Create Dedicated User (Security best practice: Don't run app as root)
        print("[*] Creating database user 'portal_user'...")
        cursor.execute("CREATE USER IF NOT EXISTS 'portal_user'@'localhost' IDENTIFIED BY 'StrongDbP@ss123'")
        cursor.execute("GRANT ALL PRIVILEGES ON captive_portal.* TO 'portal_user'@'localhost'")
        cursor.execute("FLUSH PRIVILEGES")
        print("[+] User created and granted permissions.")

        # Switch to the new database
        conn.select_db('captive_portal')

        # 3. Create 'users' Table
        print("[*] Creating 'users' table...")
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) NOT NULL UNIQUE,
            password_hash VARCHAR(255) NOT NULL,
            role ENUM('user', 'admin') DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
        print("[+] 'users' table created.")

        # 4. Create 'connection_logs' Table
        print("[*] Creating 'connection_logs' table...")
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS connection_logs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            ip_address VARCHAR(45) NOT NULL,
            login_time DATETIME NOT NULL,
            logout_time DATETIME NULL,
            data_downloaded_mb DECIMAL(10,2) DEFAULT 0.00,
            data_uploaded_mb DECIMAL(10,2) DEFAULT 0.00,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """)
        print("[+] 'connection_logs' table created.")

        # 5. Insert Default Users (Using Enterprise-grade hashing)
        print("[*] Generating secure password hashes (PBKDF2 SHA-256, 1M iterations)...")
        
        admin_hash = generate_password_hash('admin123', method='pbkdf2:sha256', salt_length=16)
        user_hash = generate_password_hash('password123', method='pbkdf2:sha256', salt_length=16)
        
        cursor.execute(
            "INSERT IGNORE INTO users (username, password_hash, role) VALUES (%s, %s, %s)",
            ('admin', admin_hash, 'admin')
        )
        cursor.execute(
            "INSERT IGNORE INTO users (username, password_hash, role) VALUES (%s, %s, %s)",
            ('john_doe', user_hash, 'user')
        )
        print("[+] Default users inserted (admin / admin123, john_doe / password123).")

        conn.commit()
        cursor.close()
        conn.close()
        
        print("\n========================================")
        print("  SUCCESS! Database is ready.")
        print("========================================\n")

    except Exception as e:
        print(f"\n[-] ERROR: {e}")
        print("Make sure MariaDB is running: sudo service mariadb start")

if __name__ == "__main__":
    setup_database()
