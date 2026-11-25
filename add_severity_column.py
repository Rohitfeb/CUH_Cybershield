
from app import app
from models_db import db

with app.app_context():

    try:
        with db.engine.begin() as connection:

            columns = connection.exec_driver_sql(
                "PRAGMA table_info(incident_report)"
            ).fetchall()

            column_names = [column[1] for column in columns]

            if "severity" in column_names:
                print("Severity column already exists!")

            else:
                connection.exec_driver_sql("""
                    ALTER TABLE incident_report
                    ADD COLUMN severity VARCHAR(30)
                    NOT NULL DEFAULT 'Unassigned'
                """)

                print("Severity column added successfully!")

    except Exception as e:
        print("Database error:", e)
