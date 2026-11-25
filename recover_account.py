"""
CUH Cyber Shield - account recovery tool.

Resets a user's password (and optionally their role) directly in the SQLite
database. It does NOT import app.py, so it works even when the app itself
cannot start because of a database / .env configuration error.

Usage (run from the project folder, with the venv active):

    python recover_account.py                 # interactive
    python recover_account.py --list          # just list the users
    python recover_account.py --db path\\to\\other.db

A timestamped backup of the database is made before any change.
"""
import argparse
import getpass
import os
import shutil
import sqlite3
import sys
from datetime import datetime

from werkzeug.security import generate_password_hash

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB = os.path.join(HERE, "instance", "cybershield.db")

# Must match User.set_password() in models_db.py
HASH_METHOD = "pbkdf2:sha256:600000"

VALID_ROLES = (
    "student",
    "faculty",
    "admin",
    "super_admin",
    "security_admin",
    "quiz_coordinator",
)


def list_users(conn):
    rows = conn.execute(
        "SELECT id, name, email, role FROM user ORDER BY id"
    ).fetchall()
    print("\nAccounts in database:")
    print(f"  {'ID':<4} {'Role':<17} {'Email':<35} Name")
    print("  " + "-" * 75)
    for uid, name, email, role in rows:
        print(f"  {uid:<4} {role:<17} {email:<35} {name}")
    print()
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("--db", default=DEFAULT_DB, help="path to the SQLite file")
    parser.add_argument("--list", action="store_true", help="only list users")
    args = parser.parse_args()

    if not os.path.isfile(args.db):
        sys.exit(f"Database not found: {args.db}")

    conn = sqlite3.connect(args.db)
    try:
        rows = list_users(conn)
        if args.list:
            return
        if not rows:
            sys.exit("No users found in this database.")

        email = input("Email of the account to recover: ").strip().lower()
        row = conn.execute(
            "SELECT id, role FROM user WHERE lower(email) = ?", (email,)
        ).fetchone()
        if row is None:
            sys.exit(f"No account with email '{email}'.")
        user_id, current_role = row

        while True:
            pw1 = getpass.getpass("New password (min 8 chars): ")
            if len(pw1) < 8:
                print("Too short - the app requires at least 8 characters.")
                continue
            pw2 = getpass.getpass("Repeat new password: ")
            if pw1 != pw2:
                print("Passwords do not match, try again.")
                continue
            break

        new_role = current_role
        answer = input(
            f"Current role is '{current_role}'. Type a new role to change it "
            f"({', '.join(VALID_ROLES)}) or press Enter to keep: "
        ).strip()
        if answer:
            if answer not in VALID_ROLES:
                sys.exit(f"Invalid role '{answer}'. Nothing was changed.")
            new_role = answer

        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup = f"{args.db}.backup_{stamp}"
        shutil.copy2(args.db, backup)
        print(f"Backup saved: {backup}")

        conn.execute(
            "UPDATE user SET password_hash = ?, role = ? WHERE id = ?",
            (generate_password_hash(pw1, method=HASH_METHOD), new_role, user_id),
        )
        conn.commit()
        print(f"\nDone. {email} can now log in (role: {new_role}).")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
