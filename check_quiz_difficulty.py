
from app import app
from models_db import db, QuizAttempt

with app.app_context():

    attempts = QuizAttempt.query.all()

    print("\nTOTAL QUIZ ATTEMPTS:", len(attempts))

    for attempt in attempts:
        print(
            "ID:", attempt.id,
            "| User ID:", attempt.user_id,
            "| Difficulty:", repr(attempt.difficulty),
            "| Score:", attempt.score
        )
