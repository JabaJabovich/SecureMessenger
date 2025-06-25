from dataclasses import dataclass
from typing import List, Optional, Iterator
import sqlite3
import json
import logging
from contextlib import contextmanager

logger = logging.getLogger(__name__)


@dataclass
class User:
    username: str
    password_hash: bytes
    salt: bytes
    public_key: str
    private_key: str
    roles: List[str]


@dataclass
class Message:
    sender: str
    recipient: str
    encrypted_data: str
    timestamp: float
    version: int = 4


class Database:
    def __init__(self, db_path: str = 'messenger.db'):
        self.db_path = db_path
        self.conn = None
        self._connect()
        logger.info(f"Database initialized: {db_path}")

    def _connect(self) -> None:
        try:
            self.conn = sqlite3.connect(self.db_path)
            self.conn.execute("PRAGMA foreign_keys = ON")
            self.conn.execute("PRAGMA journal_mode = WAL")
            self.conn.execute("PRAGMA synchronous = NORMAL")
            self._init_db()
        except sqlite3.Error as e:
            logger.error(f"Database connection error: {str(e)}")
            raise

    @contextmanager
    def _get_cursor(self) -> Iterator[sqlite3.Cursor]:
        cursor = self.conn.cursor()
        try:
            yield cursor
            self.conn.commit()
        except Exception as e:
            self.conn.rollback()
            logger.error(f"Database operation failed: {str(e)}")
            raise
        finally:
            cursor.close()

    def _init_db(self) -> None:
        with self._get_cursor() as cursor:
            # Удаляем старую таблицу messages если она существует
            cursor.execute("DROP TABLE IF EXISTS messages")

            cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash BLOB NOT NULL,
                salt BLOB NOT NULL,
                public_key TEXT NOT NULL,
                private_key TEXT NOT NULL,
                roles TEXT NOT NULL
            )''')

            cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT NOT NULL,
                recipient TEXT NOT NULL,
                encrypted_data TEXT NOT NULL,
                timestamp REAL NOT NULL,
                version INTEGER DEFAULT 4,
                FOREIGN KEY(sender) REFERENCES users(username) ON DELETE CASCADE,
                FOREIGN KEY(recipient) REFERENCES users(username) ON DELETE CASCADE
            )''')

            cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender)
            ''')
            cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient)
            ''')
            cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp)
            ''')

    def add_user(self, user: User) -> None:
        with self._get_cursor() as cursor:
            cursor.execute('''
            INSERT INTO users VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                user.username,
                user.password_hash,
                user.salt,
                user.public_key,
                user.private_key,
                json.dumps(user.roles)
            ))

    def get_user(self, username: str) -> Optional[User]:
        with self._get_cursor() as cursor:
            cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
            row = cursor.fetchone()
            if row:
                return User(
                    username=row[0],
                    password_hash=row[1],
                    salt=row[2],
                    public_key=row[3],
                    private_key=row[4],
                    roles=json.loads(row[5]))
            return None

    def save_message(self, message: Message) -> None:
        with self._get_cursor() as cursor:
            cursor.execute('''
            INSERT INTO messages (sender, recipient, encrypted_data, timestamp, version)
            VALUES (?, ?, ?, ?, ?)
            ''', (
                message.sender,
                message.recipient,
                message.encrypted_data,
                message.timestamp,
                message.version
            ))

    def get_messages(self, username: str, limit: int = 100) -> List[Message]:
        with self._get_cursor() as cursor:
            cursor.execute('''
            SELECT sender, recipient, encrypted_data, timestamp, version 
            FROM messages 
            WHERE sender = ? OR recipient = ?
            ORDER BY timestamp DESC
            LIMIT ?
            ''', (username, username, limit))
            return [Message(*row) for row in cursor.fetchall()]

    def get_conversation(self, user1: str, user2: str, limit: int = 50) -> List[Message]:
        with self._get_cursor() as cursor:
            cursor.execute('''
            SELECT sender, recipient, encrypted_data, timestamp, version 
            FROM messages 
            WHERE (sender = ? AND recipient = ?) OR (sender = ? AND recipient = ?)
            ORDER BY timestamp DESC
            LIMIT ?
            ''', (user1, user2, user2, user1, limit))
            return [Message(*row) for row in cursor.fetchall()]

    def get_all_users(self) -> List[User]:
        with self._get_cursor() as cursor:
            cursor.execute('SELECT * FROM users ORDER BY username')
            return [User(
                username=row[0],
                password_hash=row[1],
                salt=row[2],
                public_key=row[3],
                private_key=row[4],
                roles=json.loads(row[5])) for row in cursor.fetchall()]

    def get_all_messages(self, limit: int = 1000) -> List[Message]:
        with self._get_cursor() as cursor:
            cursor.execute('''
            SELECT sender, recipient, encrypted_data, timestamp, version 
            FROM messages 
            ORDER BY timestamp DESC
            LIMIT ?
            ''', (limit,))
            return [Message(*row) for row in cursor.fetchall()]

    def update_user_roles(self, username: str, roles: List[str]) -> None:
        with self._get_cursor() as cursor:
            cursor.execute('''
            UPDATE users SET roles = ? WHERE username = ?
            ''', (json.dumps(roles), username))

    def delete_user(self, username: str) -> None:
        with self._get_cursor() as cursor:
            cursor.execute('DELETE FROM users WHERE username = ?', (username,))

    def __del__(self):
        if self.conn:
            self.conn.close()
