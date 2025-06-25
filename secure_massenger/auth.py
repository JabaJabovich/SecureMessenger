import logging
from typing import Optional, List
from models import User, Database
from crypto import RSAECCEncryptor, PasswordHasher
import json

logger = logging.getLogger(__name__)


class AuthManager:
    def __init__(self, db: Database):
        self.db = db
        self.current_user = None
        logger.info("AuthManager initialized")

    def login(self, username: str, password: str) -> bool:
        try:
            if not username or not password:
                logger.warning("Empty username or password provided")
                return False

            user = self.db.get_user(username)
            if not user:
                logger.warning(f"Login attempt for non-existent user: {username}")
                return False

            if PasswordHasher.verify_password(password, user.password_hash, user.salt):
                self.current_user = user
                logger.info(f"User logged in: {username}")
                return True

            logger.warning(f"Invalid password for user: {username}")
            return False
        except Exception as e:
            logger.error(f"Login error: {str(e)}", exc_info=True)
            return False

    def logout(self) -> None:
        if self.current_user:
            logger.info(f"User logged out: {self.current_user.username}")
            self.current_user = None

    def has_permission(self, permission: str) -> bool:
        return self.current_user is not None and permission in self.current_user.roles

    def register_user(self, username: str, password: str, roles: List[str] = None) -> bool:
        try:
            roles = roles or ['user']

            if not username or not password:
                raise ValueError("Требуется имя пользователя и пароль")
            if len(username) < 3:
                raise ValueError("Имя пользователя должно быть не менее 3 символов")
            if len(password) < 8:
                raise ValueError("Пароль должен быть не менее 8 символов")

            if self.db.get_user(username):
                raise ValueError("Пользователь уже существует")

            password_hash, salt = PasswordHasher.hash_password(password)

            encryptor = RSAECCEncryptor()
            public_key, private_key = encryptor.generate_keys()
            user = User(
                username=username,
                password_hash=password_hash,
                salt=salt,
                public_key=json.dumps(public_key),
                private_key=json.dumps(private_key),
                roles=roles
            )

            self.db.add_user(user)
            logger.info(f"Registered new user: {username}")
            return True
        except Exception as e:
            logger.error(f"Registration error: {str(e)}", exc_info=True)
            raise

    def get_current_user(self) -> Optional[User]:
        return self.current_user
