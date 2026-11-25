import os
import unittest
from unittest.mock import patch

os.environ["OPENBLAS_NUM_THREADS"] = "1"
os.environ["DATABASE_URL"] = "sqlite://"
os.environ["SECRET_KEY"] = "auth-role-test-secret"
os.environ["FLASK_DEBUG"] = "1"

import app as application
from models_db import db, User


class AuthenticationRoleTests(unittest.TestCase):
    def setUp(self):
        self.app = application.app
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()
        with self.app.app_context():
            db.drop_all()
            db.create_all()

    def _create_user(self, email, role, password="valid-password"):
        user = User(name="Test Account", email=email, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        return user

    def _login(self, email, password="valid-password"):
        return self.client.post(
            "/login",
            data={"email": email, "password": password}
        )

    def test_registration_normalizes_email_and_assigns_student_role(self):
        response = self.client.post(
            "/register",
            data={
                "name": "New Student",
                "email": "Student@Example.com",
                "password": "valid-password"
            }
        )

        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.location.endswith("/login"))
        with self.app.app_context():
            user = User.query.filter_by(email="student@example.com").one()
            self.assertEqual(user.role, "student")
            self.assertNotEqual(user.password_hash, "valid-password")
            self.assertTrue(user.check_password("valid-password"))

    def test_registration_rejects_bad_email_and_duplicate_address(self):
        with self.app.app_context():
            self._create_user("existing@example.com", "student")

        invalid = self.client.post(
            "/register",
            data={
                "name": "New Student",
                "email": "not-an-email",
                "password": "valid-password"
            }
        )
        duplicate = self.client.post(
            "/register",
            data={
                "name": "Duplicate Student",
                "email": "EXISTING@example.com",
                "password": "valid-password"
            }
        )

        self.assertEqual(invalid.status_code, 302)
        self.assertEqual(duplicate.status_code, 302)
        with self.app.app_context():
            self.assertEqual(User.query.count(), 1)

    def test_login_routes_each_supported_role_to_its_dashboard(self):
        role_destinations = {
            "admin": "/admin-dashboard",
            "super_admin": "/admin-dashboard",
            "security_admin": "/security-admin-dashboard",
            "quiz_coordinator": "/quiz-coordinator-dashboard",
            "student": "/student-dashboard",
            "faculty": "/faculty-dashboard"
        }

        for index, (role, destination) in enumerate(role_destinations.items()):
            with self.subTest(role=role):
                email = f"{role}{index}@example.com"
                with self.app.app_context():
                    self._create_user(email, role)

                response = self._login(email)
                self.assertEqual(response.status_code, 302)
                self.assertTrue(response.location.endswith(destination))
                dashboard = self.client.get(destination)
                self.assertEqual(dashboard.status_code, 200)
                self.assertIn(
                    f'href="{destination}"',
                    dashboard.get_data(as_text=True)
                )
                self.client.get("/logout")

    def test_unknown_role_cannot_start_a_session(self):
        with self.app.app_context():
            self._create_user("unknown@example.com", "unknown")

        response = self._login("unknown@example.com")
        self.assertEqual(response.status_code, 200)
        self.assertIn(
            "Your account role is not authorised",
            response.get_data(as_text=True)
        )
        protected = self.client.get("/student-dashboard")
        self.assertEqual(protected.status_code, 302)
        self.assertIn("/login", protected.location)

    def test_password_hash_memory_error_shows_recovery_without_server_error(self):
        with self.app.app_context():
            self._create_user("scrypt@example.com", "super_admin")

        with patch.object(
            User,
            "check_password",
            side_effect=ValueError("malloc failure")
        ):
            response = self._login("scrypt@example.com")

        self.assertEqual(response.status_code, 200)
        self.assertIn(
            "Use Forgot Password to set it again.",
            response.get_data(as_text=True)
        )

    def test_dashboard_access_is_limited_by_role(self):
        with self.app.app_context():
            self._create_user("student@example.com", "student")
            self._create_user("faculty@example.com", "faculty")
            self._create_user("security@example.com", "security_admin")

        self._login("student@example.com")
        denied_admin = self.client.get("/admin-dashboard")
        denied_faculty = self.client.get("/faculty-dashboard")
        self.assertEqual(denied_admin.status_code, 302)
        self.assertTrue(denied_admin.location.endswith("/"))
        self.assertTrue(
            denied_faculty.location.endswith("/student-dashboard")
        )

        self.client.get("/logout")
        self._login("faculty@example.com")
        denied_student = self.client.get("/student-dashboard")
        faculty_dashboard = self.client.get("/faculty-dashboard")
        self.assertEqual(denied_student.status_code, 302)
        self.assertTrue(
            denied_student.location.endswith("/faculty-dashboard")
        )
        self.assertEqual(faculty_dashboard.status_code, 200)
        self.assertIn(
            "Faculty Dashboard",
            faculty_dashboard.get_data(as_text=True)
        )

        self.client.get("/logout")
        self._login("security@example.com")
        allowed_security = self.client.get("/security-admin-dashboard")
        denied_coordinator = self.client.get("/quiz-coordinator-dashboard")
        self.assertEqual(allowed_security.status_code, 200)
        self.assertEqual(denied_coordinator.status_code, 302)

    def test_only_super_admin_can_create_staff_accounts(self):
        with self.app.app_context():
            self._create_user("student@example.com", "student")
            self._create_user("super@example.com", "super_admin")

        self._login("student@example.com")
        denied = self.client.post(
            "/create-admin",
            data={
                "name": "Security Staff",
                "email": "security@example.com",
                "password": "valid-password",
                "role": "security_admin"
            }
        )
        self.assertEqual(denied.status_code, 302)
        self.client.get("/logout")

        self._login("super@example.com")
        created = self.client.post(
            "/create-admin",
            data={
                "name": "Security Staff",
                "email": "security@example.com",
                "password": "valid-password",
                "role": "security_admin"
            }
        )
        self.assertEqual(created.status_code, 302)
        with self.app.app_context():
            account = User.query.filter_by(email="security@example.com").one()
            self.assertEqual(account.role, "security_admin")
            self.assertTrue(account.check_password("valid-password"))

    def test_super_admin_can_change_between_all_non_super_admin_roles(self):
        source_roles = (
            "admin",
            "student",
            "faculty",
            "security_admin",
            "quiz_coordinator",
        )
        target_roles = (
            "student",
            "faculty",
            "security_admin",
            "quiz_coordinator",
        )
        role_changes = []
        with self.app.app_context():
            self._create_user("super@example.com", "super_admin")
            for source_role in source_roles:
                for target_role in target_roles:
                    if source_role == target_role:
                        continue
                    user = User(
                        name=f"{source_role} to {target_role}",
                        email=f"{source_role}-to-{target_role}@example.com",
                        password_hash="unused",
                        role=source_role,
                    )
                    db.session.add(user)
                    db.session.flush()
                    role_changes.append((user.id, target_role))
            db.session.commit()

        self._login("super@example.com")
        dashboard = self.client.get("/admin-dashboard")
        dashboard_text = dashboard.get_data(as_text=True)
        self.assertIn("Change Student, Faculty, or Admin Accounts", dashboard_text)
        self.assertIn("Select a role", dashboard_text)
        self.assertNotIn('value="admin"', dashboard_text)
        for role in target_roles:
            self.assertIn(f'value="{role}"', dashboard_text)

        for user_id, target_role in role_changes:
            with self.subTest(target_role=target_role):
                response = self.client.post(
                    f"/admin/change-user-role/{user_id}",
                    data={"role": target_role}
                )
                self.assertEqual(response.status_code, 302)

        with self.app.app_context():
            for user_id, target_role in role_changes:
                self.assertEqual(
                    db.session.get(User, user_id).role,
                    target_role
                )

    def test_super_admin_can_change_staff_accounts_to_student_or_faculty(self):
        with self.app.app_context():
            self._create_user("super@example.com", "super_admin")
            security_admin = self._create_user(
                "security@example.com",
                "security_admin"
            )
            coordinator = self._create_user(
                "coordinator@example.com",
                "quiz_coordinator"
            )
            security_admin_id = security_admin.id
            coordinator_id = coordinator.id

        self._login("super@example.com")
        dashboard = self.client.get("/admin-dashboard")
        dashboard_text = dashboard.get_data(as_text=True)
        self.assertIn(
            "Change Existing Security Admin or Quiz Coordinator",
            dashboard_text
        )
        self.assertIn("security@example.com", dashboard_text)
        self.assertIn("coordinator@example.com", dashboard_text)

        for user_id, role in (
            (security_admin_id, "student"),
            (coordinator_id, "faculty"),
        ):
            with self.subTest(role=role):
                response = self.client.post(
                    f"/admin/change-user-role/{user_id}",
                    data={"role": role}
                )
                self.assertEqual(response.status_code, 302)

        with self.app.app_context():
            self.assertEqual(
                db.session.get(User, security_admin_id).role,
                "student"
            )
            self.assertEqual(
                db.session.get(User, coordinator_id).role,
                "faculty"
            )

        security_client = self.app.test_client()
        security_login = security_client.post(
            "/login",
            data={
                "email": "security@example.com",
                "password": "valid-password",
            }
        )
        self.assertTrue(
            security_login.location.endswith("/student-dashboard")
        )
        self.assertEqual(
            security_client.get("/security-admin-dashboard").status_code,
            302
        )

        coordinator_client = self.app.test_client()
        coordinator_login = coordinator_client.post(
            "/login",
            data={
                "email": "coordinator@example.com",
                "password": "valid-password",
            }
        )
        self.assertTrue(
            coordinator_login.location.endswith("/faculty-dashboard")
        )
        self.assertEqual(
            coordinator_client.get(
                "/quiz-coordinator-dashboard"
            ).status_code,
            302
        )

    def test_role_management_tables_paginate_independently(self):
        with self.app.app_context():
            self._create_user("super@example.com", "super_admin")
            for index in range(11):
                db.session.add(User(
                    name=f"Student {index:02}",
                    email=f"student-{index:02}@example.com",
                    password_hash="unused",
                    role="student",
                ))
                db.session.add(User(
                    name=f"Staff {index:02}",
                    email=f"staff-{index:02}@example.com",
                    password_hash="unused",
                    role=(
                        "security_admin"
                        if index % 2 == 0
                        else "quiz_coordinator"
                    ),
                ))
            db.session.commit()

        self._login("super@example.com")
        first_page = self.client.get("/admin-dashboard")
        first_page_text = first_page.get_data(as_text=True)
        student_section = first_page_text.split(
            "Change Student, Faculty, or Admin Accounts",
            1
        )[1].split(
            "Change Existing Security Admin or Quiz Coordinator",
            1
        )[0]
        staff_section = first_page_text.split(
            "Change Existing Security Admin or Quiz Coordinator",
            1
        )[1]
        self.assertIn("student-00@example.com", student_section)
        self.assertNotIn("student-10@example.com", student_section)
        self.assertIn("staff-00@example.com", staff_section)
        self.assertNotIn("staff-10@example.com", staff_section)

        second_page = self.client.get(
            "/admin-dashboard?student_accounts_page=2"
            "&staff_accounts_page=2&difficulty=Beginner&page=2"
        )
        second_page_text = second_page.get_data(as_text=True)
        student_section = second_page_text.split(
            "Change Student, Faculty, or Admin Accounts",
            1
        )[1].split(
            "Change Existing Security Admin or Quiz Coordinator",
            1
        )[0]
        staff_section = second_page_text.split(
            "Change Existing Security Admin or Quiz Coordinator",
            1
        )[1]
        self.assertIn("student-10@example.com", student_section)
        self.assertNotIn("student-00@example.com", student_section)
        self.assertIn("staff-10@example.com", staff_section)
        self.assertNotIn("staff-00@example.com", staff_section)
        self.assertIn("difficulty=Beginner", second_page_text)

    def test_only_super_admin_can_change_roles_and_super_admin_is_protected(self):
        with self.app.app_context():
            student = self._create_user("student@example.com", "student")
            super_admin = self._create_user("super@example.com", "super_admin")
            student_id = student.id
            super_admin_id = super_admin.id

        self._login("student@example.com")
        denied = self.client.post(
            f"/admin/change-user-role/{student_id}",
            data={"role": "security_admin"}
        )
        self.assertEqual(denied.status_code, 302)
        self.client.get("/logout")

        self._login("super@example.com")
        invalid_role = self.client.post(
            f"/admin/change-user-role/{student_id}",
            data={"role": "super_admin"}
        )
        privileged_target = self.client.post(
            f"/admin/change-user-role/{super_admin_id}",
            data={"role": "quiz_coordinator"}
        )
        self.assertEqual(invalid_role.status_code, 302)
        self.assertEqual(privileged_target.status_code, 302)

        with self.app.app_context():
            self.assertEqual(
                db.session.get(User, student_id).role,
                "student"
            )
            self.assertEqual(
                db.session.get(User, super_admin_id).role,
                "super_admin"
            )


if __name__ == "__main__":
    unittest.main()
