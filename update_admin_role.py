
import sqlite3
import os

DB_PATH = os.path.join("instance", "cybershield.db")

print("Connecting to database...")

try:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute(
        """
        UPDATE user
        SET role = ?
        WHERE email = ? AND role = ?
        """,
        (
            "super_admin",
            "rohitdbg177@gmail.com",
            "admin"
        )
    )

    conn.commit()

    print("Updated accounts:", cursor.rowcount)

    cursor.execute(
        "SELECT id, name, email, role FROM user"
    )

    print("\nCurrent user accounts:")

    for user in cursor.fetchall():
        print(user)

    conn.close()
    print("\nDatabase operation completed.")

except Exception as error:
    print("Error:", error)
