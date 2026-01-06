
import mysql.connector
from config import Config
import fix_schema_direct
import apply_schema

def reset_database():
    print("[-] Connecting to MySQL server to reset database...")
    # Connect to MySQL server (not specific DB yet usually, but here we can connect to DB to drop it)
    # Or validly, connect without DB to drop DB.
    
    # Try connecting without database first to drop it
    try:
        conn = mysql.connector.connect(
            host=Config.DB_HOST,
            user=Config.DB_USER,
            password=Config.DB_PASSWORD
        )
        cursor = conn.cursor()
        
        print(f"[-] Dropping database {Config.DB_NAME} if exists...")
        cursor.execute(f"DROP DATABASE IF EXISTS {Config.DB_NAME}")
        
        print(f"[-] Creating database {Config.DB_NAME}...")
        cursor.execute(f"CREATE DATABASE {Config.DB_NAME}")
        cursor.execute(f"USE {Config.DB_NAME}")
        
        print("[-] Applying base schema.sql...")
        with open('schema.sql', 'r') as f:
            # schema.sql might have multiple statements and CREATE DATABASE in it too.
            # Let's read it and execute statements.
            # schema.sql lines:
            # CREATE DATABASE IF NOT EXISTS iot_security;
            # USE iot_security;
            # CREATE TABLE ...
            
            # Since we just created DB, we can skip the CREATE DATABASE part or let it run.
            sqls = f.read().split(';')
            for s in sqls:
                if s.strip():
                    try:
                        cursor.execute(s)
                    except Exception as e:
                        print(f"[!] Error executing schema.sql stmt: {e} \nStmt: {s[:50]}...")
                        
        conn.commit()
        cursor.close()
        conn.close()
        print("[+] Base schema applied.")
        
    except Exception as e:
        print(f"[!] Critical Error resetting DB: {e}")
        return

    # Now apply fixes
    print("[-] Applying Schema Fixes (Direct)...")
    fix_schema_direct.fix_schema()
    
    print("[-] Applying Schema Fixes (SQL Updates)...")
    apply_schema.apply_update()
    
    print("[+] Database Reset and Rebuilt Successfully.")

if __name__ == "__main__":
    reset_database()
