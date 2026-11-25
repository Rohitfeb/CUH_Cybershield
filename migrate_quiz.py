
import os
import sqlite3

from app import app
from models_db import db

with app.app_context():

    # Get the actual SQLite database location
    db_path = db.engine.url.database

    if not db_path or db_path == ":memory:":
        raise RuntimeError("SQLite database path not found.")

    db_path = os.path.abspath(db_path)

    if not os.path.exists(db_path):
        raise FileNotFoundError(f"Database not found: {db_path}")

    # Create a backup before changing anything
    backup_path = db_path + ".before_difficulty_backup"

    with sqlite3.connect(db_path) as source:
        with sqlite3.connect(backup_path) as backup:
            source.backup(backup)

    print("Database backup created:", backup_path)

    # Add difficulty column if it does not already exist
    with sqlite3.connect(db_path) as connection:

        columns = connection.execute(
            "PRAGMA table_info(quiz_attempt)"
        ).fetchall()

        if not columns:
            raise RuntimeError("quiz_attempt table not found.")

        column_names = [column[1] for column in columns]

        if "difficulty" not in column_names:

            connection.execute("""
                ALTER TABLE quiz_attempt
                ADD COLUMN difficulty VARCHAR(30)
                NOT NULL DEFAULT 'Mixed'
            """)

            connection.commit()

            print("Difficulty column added successfully.")

        else:
            print("Difficulty column already exists.")

print("Database migration completed!")