from app import app
from models_db import User

with app.app_context():
    users = User.query.all()

    for user in users:
        print(
            "ID:", user.id,
            "| Name:", user.name,
            "| Email:", user.email,
            "| Role:", user.role
        )