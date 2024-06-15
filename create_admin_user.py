import mysql.connector
from werkzeug.security import generate_password_hash

db_config = {
    'user': 'root',
    'password': '',
    'host': 'localhost',
    'database': 'email_extraction_tool'
}

def create_admin_user(username, email, password):
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()
    hashed_password = generate_password_hash(password)
    try:
        cursor.execute("INSERT INTO users (username, email, password, is_admin) VALUES (%s, %s, %s, %s)", 
                       (username, email, hashed_password, True))
        conn.commit()
        print('Admin user created successfully.')
    except mysql.connector.Error as err:
        print(f"Error: {err}")
    finally:
        cursor.close()
        conn.close()

if __name__ == "__main__":
    create_admin_user('admin', 'admin@mail.com', 'admin123')
