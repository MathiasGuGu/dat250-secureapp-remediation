import hashlib
import os
import uuid

import psycopg2
import pytest
import requests

BASE_URL = os.getenv("BASE_URL", "http://127.0.0.1:18181")
DB_URL = os.getenv("TEST_DATABASE_URL", "postgresql://dat250:dat250@127.0.0.1:15432/dat250")

ADMIN = ("admin@dat250.local", "Admin123")
TEACHER = ("teacher@dat250.local", "Teacher123")
ALICE = ("alice@student.uis.no", "Alice123")
BOB = ("bob@student.uis.no", "Bob123")


def db(query, params=()):
    conn = psycopg2.connect(DB_URL)
    try:
        with conn.cursor() as cur:
            cur.execute(query, params)
            rows = cur.fetchall() if cur.description else None
        conn.commit()
        return rows
    finally:
        conn.close()


def login(email, password):
    session = requests.Session()
    r = session.post(f"{BASE_URL}/login", data={"email": email, "password": password}, allow_redirects=False)
    assert r.status_code == 302 and r.headers["location"] == "/dashboard", f"login failed for {email}"
    return session


def role_of(user_id):
    return db("SELECT role FROM users WHERE id=%s", (user_id,))[0][0]


def hash_of(user_id):
    return db("SELECT password_hash FROM users WHERE id=%s", (user_id,))[0][0]


@pytest.fixture
def make_student():
    created = []

    def _make(password="Regress123"):
        email = f"regress_{uuid.uuid4().hex[:10]}@student.uis.no"
        requests.post(
            f"{BASE_URL}/register",
            data={"email": email, "full_name": "Regression Student", "password": password},
            allow_redirects=False,
        )
        user_id = db("SELECT id FROM users WHERE email=%s", (email,))[0][0]
        created.append(user_id)
        return {"session": login(email, password), "id": user_id, "email": email, "password": password}

    yield _make
    for user_id in created:
        db("DELETE FROM sessions WHERE user_id=%s", (user_id,))
        db("DELETE FROM users WHERE id=%s", (user_id,))


@pytest.fixture
def student(make_student):
    return make_student()


@pytest.fixture
def grade_1():
    original = db("SELECT grade_value, feedback, status FROM grades WHERE id=1")[0]
    yield original
    db("UPDATE grades SET grade_value=%s, feedback=%s, status=%s WHERE id=1", original)


# F01: SSRF in the resource importer

def test_f01_import_requires_login():
    r = requests.get(f"{BASE_URL}/resources/import", params={"url": "http://mailhog:8025/"}, allow_redirects=False)
    assert r.status_code == 302
    assert r.headers["location"] == "/login"


@pytest.mark.parametrize(
    "url",
    [
        "http://mailhog:8025/",
        "http://backend:8000/health",
        "http://db:5432/",
        "http://127.0.0.1:8000/",
        "http://localhost/",
        "http://0x7f000001/",
        "http://[::1]/",
        "http://169.254.169.254/latest/meta-data/",
        "http://example.com@mailhog:8025/",
        "file:///etc/passwd",
        "gopher://mailhog:8025/",
    ],
)
def test_f01_internal_and_non_http_destinations_are_blocked(student, url):
    r = student["session"].get(f"{BASE_URL}/resources/import", params={"url": url})
    assert "Destination not allowed" in r.text
    assert "MailHog" not in r.text
    assert "&#34;status&#34;" not in r.text


def test_f01_public_url_still_imports(student):
    r = student["session"].get(f"{BASE_URL}/resources/import", params={"url": "https://example.com/"})
    assert "Example Domain" in r.text


# F02: role taken from the profile form

def test_f02_profile_update_ignores_role(student):
    r = student["session"].post(
        f"{BASE_URL}/profile/update",
        data={"full_name": "Renamed Student", "phone": "", "address": "", "bio": "", "role": "admin"},
        allow_redirects=False,
    )
    assert r.status_code == 302
    full_name, role = db("SELECT full_name, role FROM users WHERE id=%s", (student["id"],))[0]
    assert full_name == "Renamed Student"
    assert role == "student"


# F02b: role change endpoint and admin pages without a server-side role check

def test_f02b_student_cannot_change_roles(student):
    r = student["session"].post(
        f"{BASE_URL}/admin/users/{student['id']}/role",
        data={"role": "admin"},
        headers={"x-role": "admin"},
        allow_redirects=False,
    )
    assert r.status_code == 403
    assert role_of(student["id"]) == "student"


def test_f02b_admin_can_change_roles(student):
    r = login(*ADMIN).post(f"{BASE_URL}/admin/users/{student['id']}/role", data={"role": "ta"}, allow_redirects=False)
    assert r.status_code == 302
    assert role_of(student["id"]) == "ta"


def test_f02b_admin_cannot_set_unknown_role(student):
    r = login(*ADMIN).post(
        f"{BASE_URL}/admin/users/{student['id']}/role", data={"role": "superuser"}, allow_redirects=False
    )
    assert r.status_code == 400
    assert role_of(student["id"]) == "student"


@pytest.mark.parametrize("path", ["/admin/users", "/admin/grades", "/admin/search-users?q=a"])
def test_f02b_admin_pages_forbidden_for_students(student, path):
    r = student["session"].get(f"{BASE_URL}{path}", allow_redirects=False)
    assert r.status_code == 403


@pytest.mark.parametrize("path", ["/admin/users", "/admin/grades"])
def test_f02b_admin_pages_available_to_staff(path):
    r = login(*TEACHER).get(f"{BASE_URL}{path}", allow_redirects=False)
    assert r.status_code == 200


# F03: grade update authorized by a client-supplied role

def test_f03_student_cannot_update_grade_with_forged_role(student, grade_1):
    r = student["session"].post(
        f"{BASE_URL}/admin/grades/1/update",
        data={"grade_value": "A+PWNED", "feedback": "INTEGRITY-MARKER-F03", "role": "teacher"},
        allow_redirects=False,
    )
    assert r.status_code == 403
    assert db("SELECT grade_value, feedback, status FROM grades WHERE id=1")[0] == grade_1


def test_f03_teacher_can_update_grade(grade_1):
    r = login(*TEACHER).post(
        f"{BASE_URL}/admin/grades/1/update",
        data={"grade_value": "A-", "feedback": "Regression test feedback"},
        allow_redirects=False,
    )
    assert r.status_code == 302
    assert db("SELECT grade_value, feedback FROM grades WHERE id=1")[0] == ("A-", "Regression test feedback")


# F04: unsalted SHA-256 password storage

def test_f04_new_passwords_are_stored_as_argon2id(student):
    stored = hash_of(student["id"])
    assert stored.startswith("$argon2id$")
    assert stored != hashlib.sha256(student["password"].encode()).hexdigest()


def test_f04_same_password_gives_different_hashes(make_student):
    first = make_student(password="Same12345")
    second = make_student(password="Same12345")
    assert hash_of(first["id"]) != hash_of(second["id"])


def test_f04_wrong_password_is_rejected(student):
    r = requests.post(
        f"{BASE_URL}/login", data={"email": student["email"], "password": "wrong"}, allow_redirects=False
    )
    assert r.status_code == 200
    assert "session_token" not in r.cookies


def test_f04_legacy_sha256_hash_is_upgraded_on_login(student):
    legacy = hashlib.sha256(student["password"].encode()).hexdigest()
    db("UPDATE users SET password_hash=%s WHERE id=%s", (legacy, student["id"]))
    login(student["email"], student["password"])
    assert hash_of(student["id"]).startswith("$argon2id$")


# F05: IDOR on message detail

def test_f05_non_participant_cannot_read_message(student):
    r = student["session"].get(f"{BASE_URL}/messages/1", allow_redirects=False)
    assert r.status_code == 404
    assert "Please remember to include screenshots" not in r.text


def test_f05_other_student_cannot_read_message():
    r = login(*BOB).get(f"{BASE_URL}/messages/1", allow_redirects=False)
    assert r.status_code == 404


@pytest.mark.parametrize("account", [ALICE, TEACHER], ids=["recipient", "sender"])
def test_f05_participants_can_read_message(account):
    r = login(*account).get(f"{BASE_URL}/messages/1", allow_redirects=False)
    assert r.status_code == 200
    assert "Please remember to include screenshots" in r.text


def test_f05_unknown_message_is_not_found(student):
    r = student["session"].get(f"{BASE_URL}/messages/999999", allow_redirects=False)
    assert r.status_code == 404
