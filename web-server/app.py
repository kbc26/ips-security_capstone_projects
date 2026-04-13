
from datetime import datetime, timedelta
import time
import re

from flask import Flask, request, session, redirect, url_for, render_template, jsonify
import mysql.connector
from werkzeug.security import check_password_hash

app = Flask(__name__)
app.secret_key = "CHANGE_THIS_TO_A_REAL_SECRET_KEY"

DB_CONFIG = {
    "host": "192.168.2.200",
    "user": "webuser",
    "password": "1234",
    "database": "login_db",
    "autocommit": True
}

MAX_FAILED_COUNT = 10
LOCK_MINUTES = 15
IP_WINDOW_MINUTES = 10
IP_MAX_FAILS = 20


def get_db():
    return mysql.connector.connect(**DB_CONFIG)


def get_client_ip():
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"


def detect_sqli(input_text):
    if not input_text:
        return False

    patterns = [
        r"(?i)\bor\b\s+1=1",
        r"(?i)'\s*or\s*'1'\s*=\s*'1",
        r"(?i)'\s*or\s*1=1\s*--",
        r"(?i)union\s+select",
        r"(?i)drop\s+table",
        r"(?i)insert\s+into",
        r"(?i)delete\s+from",
        r"(?i)update\s+\w+\s+set",
        r"(?i)--",
        r"(?i)#",
        r"(?i)/\*.*\*/"
    ]

    for pattern in patterns:
        if re.search(pattern, input_text):
            return True
    return False


def log_login_attempt(username, success, client_ip, reason=""):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO login_logs (input_id, success, client_ip, reason, created_at)
        VALUES (%s, %s, %s, %s, NOW())
        """,
        (username, 1 if success else 0, client_ip, reason)
    )
    cur.close()
    conn.close()


def get_recent_failed_count_by_ip(client_ip):
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute(
        """
        SELECT COUNT(*) AS cnt
        FROM login_logs
        WHERE client_ip = %s
          AND success = 0
          AND created_at >= (NOW() - INTERVAL %s MINUTE)
        """,
        (client_ip, IP_WINDOW_MINUTES)
    )
    row = cur.fetchone()
    cur.close()
    conn.close()
    return row["cnt"] if row else 0


def get_user_by_username(username):
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute(
        """
        SELECT id, username, password_hash, role, failed_count, locked_until
        FROM users
        WHERE username = %s
        """,
        (username,)
    )
    user = cur.fetchone()
    cur.close()
    conn.close()
    return user


def reset_user_fail_state(user_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        UPDATE users
        SET failed_count = 0,
            locked_until = NULL
        WHERE id = %s
        """,
        (user_id,)
    )
    cur.close()
    conn.close()


def register_user_fail(user_id):
    conn = get_db()
    cur = conn.cursor(dictionary=True)

    cur.execute(
        "SELECT failed_count FROM users WHERE id = %s",
        (user_id,)
    )
    row = cur.fetchone()
    failed_count = (row["failed_count"] if row else 0) + 1

    if failed_count >= MAX_FAILED_COUNT:
        cur.execute(
            """
            UPDATE users
            SET failed_count = %s,
                locked_until = %s
            WHERE id = %s
            """,
            (failed_count, datetime.now() + timedelta(minutes=LOCK_MINUTES), user_id)
        )
    else:
        cur.execute(
            """
            UPDATE users
            SET failed_count = %s
            WHERE id = %s
            """,
            (failed_count, user_id)
        )

    cur.close()
    conn.close()
    return failed_count


def is_logged_in():
    return "user_id" in session


def is_admin():
    return session.get("role") == "admin"


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/login", methods=["POST"])
def login():

    if request.method == "POST":
    	username = request.form.get("username", "").strip()
    	password = request.form.get("password", "").strip()


    client_ip = get_client_ip()

    # SQL Injection 시도 탐지
    if detect_sqli(username) or detect_sqli(password):
        log_login_attempt(username if username else "unknown", False, client_ip, reason="sqli_attempt")
        time.sleep(0.8)
        return jsonify({"message": "로그인에 실패했습니다."}), 400

    # IP 기준 추가 제한
    recent_ip_fails = get_recent_failed_count_by_ip(client_ip)
    if recent_ip_fails >= IP_MAX_FAILS:
        log_login_attempt(username if username else "unknown", False, client_ip, reason="ip_rate_limited")
        time.sleep(1.0)
        return jsonify({"message": "로그인에 실패했습니다."}), 429

    user = get_user_by_username(username)

    # 존재하지 않는 계정도 동일한 메시지
    if not user:
        log_login_attempt(username if username else "unknown", False, client_ip, reason="unknown_user")
        time.sleep(0.8)
        return jsonify({"message": "로그인에 실패했습니다."}), 401

    # 계정 잠금 여부 체크
    locked_until = user["locked_until"]
    if locked_until and locked_until > datetime.now():
        log_login_attempt(username, False, client_ip, reason="account_locked")
        time.sleep(1.0)
        return jsonify({"message": "로그인에 실패했습니다."}), 423

    # 비밀번호 검증
    if check_password_hash(user["password_hash"], password):
        reset_user_fail_state(user["id"])
        log_login_attempt(username, True, client_ip, reason="login_success")

        session.clear()
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["role"] = user["role"]
        session["client_ip"] = client_ip

        if user["role"] == "admin":
            return redirect(url_for("admin"))
        return redirect(url_for("dashboard"))

    # 실패 처리
    failed_count = register_user_fail(user["id"])

    if failed_count >= MAX_FAILED_COUNT:
        log_login_attempt(username, False, client_ip, reason="account_locked_after_fail")
    else:
        log_login_attempt(username, False, client_ip, reason="bad_password")

    time.sleep(0.8)
    return jsonify({"message": "로그인에 실패했습니다."}), 401


@app.route("/dashboard", methods=["GET"])
def dashboard():
    if not is_logged_in():
        return redirect(url_for("index"))

    return render_template(
        "dashboard.html",
        username=session.get("username"),
        role=session.get("role"),
        client_ip=session.get("client_ip")
    )


@app.route("/admin", methods=["GET"])
def admin():
    if not is_logged_in():
        log_login_attempt("unknown", False, get_client_ip(), reason="unauthorized_admin_access")
        return redirect(url_for("index"))

    if not is_admin():
        log_login_attempt(session.get("username", "unknown"), False, get_client_ip(), reason="forbidden_admin_access")
        return jsonify({"message": "접근 권한이 없습니다."}), 403

    conn = get_db()
    cur = conn.cursor(dictionary=True)

    cur.execute(
        """
        SELECT
            COUNT(*) AS total_attempts,
            SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) AS success_count,
            SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) AS fail_count
        FROM login_logs
        """
    )
    stats = cur.fetchone()

    cur.execute(
        """
        SELECT input_id, success, client_ip, reason, created_at
        FROM login_logs
        ORDER BY created_at DESC
        LIMIT 20
        """
    )
    recent_logs = cur.fetchall()

    cur.execute(
        """
        SELECT client_ip, COUNT(*) AS fail_count
        FROM login_logs
        WHERE success = 0
        GROUP BY client_ip
        ORDER BY fail_count DESC
        LIMIT 10
        """
    )
    top_attack_ips = cur.fetchall()

    cur.execute(
        """
        SELECT username, failed_count, locked_until
        FROM users
        WHERE locked_until IS NOT NULL
          AND locked_until > NOW()
        ORDER BY locked_until DESC
        """
    )
    locked_users = cur.fetchall()

    cur.close()
    conn.close()

    return render_template(
        "admin.html",
        username=session.get("username"),
        stats=stats,
        recent_logs=recent_logs,
        top_attack_ips=top_attack_ips,
        locked_users=locked_users
    )


@app.route("/logs", methods=["GET"])
def logs():
    if not is_logged_in():
        return redirect(url_for("index"))

    if not is_admin():
        log_login_attempt(session.get("username", "unknown"), False, get_client_ip(), reason="forbidden_logs_access")
        return jsonify({"message": "접근 권한이 없습니다."}), 403

    status_filter = request.args.get("status", "").strip()
    reason_filter = request.args.get("reason", "").strip()
    ip_filter = request.args.get("ip", "").strip()

    query = """
        SELECT input_id, success, client_ip, reason, created_at
        FROM login_logs
        WHERE 1=1
    """
    params = []

    if status_filter == "success":
        query += " AND success = 1"
    elif status_filter == "fail":
        query += " AND success = 0"

    if reason_filter:
        query += " AND reason = %s"
        params.append(reason_filter)

    if ip_filter:
        query += " AND client_ip = %s"
        params.append(ip_filter)

    query += " ORDER BY created_at DESC LIMIT 200"

    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute(query, tuple(params))
    logs = cur.fetchall()
    cur.close()
    conn.close()

    return render_template(
        "logs.html",
        logs=logs,
        status_filter=status_filter,
        reason_filter=reason_filter,
        ip_filter=ip_filter
    )


@app.route("/admin/users", methods=["GET"])
def admin_users():
    if not is_logged_in():
        return redirect(url_for("index"))

    if not is_admin():
        log_login_attempt(session.get("username", "unknown"), False, get_client_ip(), reason="forbidden_user_admin_access")
        return jsonify({"message": "접근 권한이 없습니다."}), 403

    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute(
        """
        SELECT id, username, role, failed_count, locked_until
        FROM users
        ORDER BY id ASC
        """
    )
    users = cur.fetchall()
    cur.close()
    conn.close()

    return render_template(
        "admin_users.html",
        users=users,
        username=session.get("username")
    )


@app.route("/admin/unlock/<int:user_id>", methods=["POST"])
def unlock_user(user_id):
    if not is_logged_in():
        return redirect(url_for("index"))

    if not is_admin():
        log_login_attempt(session.get("username", "unknown"), False, get_client_ip(), reason="forbidden_unlock_access")
        return jsonify({"message": "접근 권한이 없습니다."}), 403

    reset_user_fail_state(user_id)
    return redirect(url_for("admin_users"))


@app.route("/logout", methods=["GET"])
def logout():
    session.clear()
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
