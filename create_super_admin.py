"""
Create (or reset) the super admin in whatever database DATABASE_URL points to.
Run ONCE from your own computer after the Postgres database exists:

    PowerShell:
      $env:DATABASE_URL = "postgresql+psycopg://USER:PASS@HOST/DB?sslmode=require"
      $env:DEPLOYMENT_ENV = "development"
      python create_super_admin.py

Importing app creates all tables automatically (db.create_all) if they are missing.
"""
import getpass
import os
import sys

if not os.environ.get("DATABASE_URL"):
    sys.exit("Set DATABASE_URL first (see the instructions at the top of this file).")

from app import app            # noqa: E402  (creates tables on import)
from models_db import db, User  # noqa: E402

email = input("Super admin email: ").strip().lower()
name = input("Full name: ").strip()
while True:
    pw = getpass.getpass("Password (min 8 chars): ")
    if len(pw) >= 8 and pw == getpass.getpass("Repeat password: "):
        break
    print("Too short or not matching, try again.")

with app.app_context():
    user = User.query.filter_by(email=email).first()
    if user is None:
        user = User(name=name, email=email, role="super_admin")
        db.session.add(user)
        action = "Created"
    else:
        user.role = "super_admin"
        action = "Updated"
    user.set_password(pw)
    db.session.commit()
    print(f"{action} super admin: {email}")
