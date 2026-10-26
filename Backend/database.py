import os
import sqlite3

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "ctia.db")


def get_db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def add_column_if_missing(connection, table, column, definition):
    cursor = connection.cursor()

    cursor.execute(f"PRAGMA table_info({table})")
    columns = [row["name"] for row in cursor.fetchall()]

    if column not in columns:
        cursor.execute(
            f"ALTER TABLE {table} ADD COLUMN {column} {definition}"
        )


def initialize_database():

    connection = get_db()
    cursor = connection.cursor()

    # ==========================================
    # USERS
    # ==========================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # ==========================================
    # THREATS
    # ==========================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS threats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator TEXT NOT NULL,
            threat_type TEXT,
            severity TEXT,
            source TEXT,
            description TEXT,
            risk_score INTEGER DEFAULT 0,
            confidence INTEGER DEFAULT 0,
            indicator_type TEXT DEFAULT 'Unknown',
            status TEXT DEFAULT 'Active',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Support older database versions
    add_column_if_missing(
        connection,
        "threats",
        "risk_score",
        "INTEGER DEFAULT 0"
    )

    add_column_if_missing(
        connection,
        "threats",
        "confidence",
        "INTEGER DEFAULT 0"
    )

    add_column_if_missing(
        connection,
        "threats",
        "indicator_type",
        "TEXT DEFAULT 'Unknown'"
    )

    add_column_if_missing(
        connection,
        "threats",
        "status",
        "TEXT DEFAULT 'Active'"
    )

    # ==========================================
    # ALERTS
    # ==========================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            severity TEXT,
            status TEXT DEFAULT 'Open',
            source TEXT,
            indicator TEXT,
            threat_type TEXT,
            risk_score INTEGER DEFAULT 0,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    add_column_if_missing(
        connection,
        "alerts",
        "indicator",
        "TEXT"
    )

    add_column_if_missing(
        connection,
        "alerts",
        "threat_type",
        "TEXT"
    )

    add_column_if_missing(
        connection,
        "alerts",
        "risk_score",
        "INTEGER DEFAULT 0"
    )

    add_column_if_missing(
        connection,
        "alerts",
        "description",
        "TEXT"
    )

    # ==========================================
    # IOC REPOSITORY
    # ==========================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator TEXT UNIQUE NOT NULL,
            indicator_type TEXT,
            threat_type TEXT,
            severity TEXT,
            risk_score INTEGER DEFAULT 0,
            confidence INTEGER DEFAULT 0,
            source TEXT,
            status TEXT DEFAULT 'Active',
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # ==========================================
    # OSINT RECORDS
    # ==========================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS osint_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT NOT NULL,
            title TEXT,
            indicator TEXT,
            indicator_type TEXT,
            threat_type TEXT,
            severity TEXT,
            description TEXT,
            url TEXT,
            collected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    connection.commit()
    connection.close()


# ==========================================
# USER FUNCTIONS
# ==========================================

def create_user(name, email, password):

    connection = get_db()
    cursor = connection.cursor()

    hashed_password = generate_password_hash(password)

    try:

        cursor.execute(
            """
            INSERT INTO users
            (name, email, password)
            VALUES (?, ?, ?)
            """,
            (
                name,
                email,
                hashed_password
            )
        )

        connection.commit()

        user_id = cursor.lastrowid

        connection.close()

        return user_id

    except sqlite3.IntegrityError:

        connection.close()

        return None


def authenticate_user(email, password):

    connection = get_db()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT *
        FROM users
        WHERE email = ?
        """,
        (email,)
    )

    user = cursor.fetchone()

    connection.close()

    if user:

        if check_password_hash(
            user["password"],
            password
        ):
            return user

    return None