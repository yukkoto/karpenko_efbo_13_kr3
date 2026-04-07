import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Callable

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBasic, HTTPBasicCredentials, HTTPBearer
from passlib.context import CryptContext

from .database import get_db_connection

pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')
security_basic = HTTPBasic(auto_error=True)
security_bearer = HTTPBearer(auto_error=False)

JWT_SECRET = os.getenv('JWT_SECRET', 'super-secret-key-change-me')
JWT_ALGORITHM = 'HS256'
JWT_EXPIRE_MINUTES = int(os.getenv('JWT_EXPIRE_MINUTES', '30'))

ROLE_PERMISSIONS = {
    'admin': {'create', 'read', 'update', 'delete'},
    'user': {'read', 'update'},
    'guest': {'read'},
}


class SimpleRateLimiter:
    def __init__(self) -> None:
        self._storage: dict[tuple[str, str], list[datetime]] = {}

    def limit(self, key_prefix: str, times: int, seconds: int) -> Callable:
        def decorator(func: Callable) -> Callable:
            async def wrapper(*args, **kwargs):
                request: Request | None = kwargs.get('request')
                if request is None:
                    for arg in args:
                        if isinstance(arg, Request):
                            request = arg
                            break
                if request is None:
                    raise RuntimeError('Request is required for rate limiter')

                client_ip = request.client.host if request.client else 'unknown'
                key = (key_prefix, client_ip)
                now = datetime.now(timezone.utc)
                window_start = now - timedelta(seconds=seconds)
                entries = [dt for dt in self._storage.get(key, []) if dt > window_start]
                if len(entries) >= times:
                    raise HTTPException(status_code=429, detail='Too many requests')
                entries.append(now)
                self._storage[key] = entries
                return await func(*args, **kwargs)

            return wrapper

        return decorator


rate_limiter = SimpleRateLimiter()


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def _fetch_user_row_by_digest(username: str):
    conn = get_db_connection()
    rows = conn.execute('SELECT id, username, password, role FROM users').fetchall()
    conn.close()
    for row in rows:
        if secrets.compare_digest(row['username'], username):
            return row
    return None


def auth_user(credentials: HTTPBasicCredentials = Depends(security_basic)):
    auth_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail='Invalid credentials',
        headers={'WWW-Authenticate': 'Basic'},
    )

    user_row = _fetch_user_row_by_digest(credentials.username)
    if not user_row:
        raise auth_error

    if not verify_password(credentials.password, user_row['password']):
        raise auth_error

    return {
        'id': user_row['id'],
        'username': user_row['username'],
        'role': user_row['role'],
    }


def create_access_token(subject: str, role: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        'sub': subject,
        'role': role,
        'iat': int(now.timestamp()),
        'exp': int((now + timedelta(minutes=JWT_EXPIRE_MINUTES)).timestamp()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security_bearer)):
    if credentials is None:
        raise HTTPException(status_code=401, detail='Missing token')
    token = credentials.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail='Token expired')
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail='Invalid token')

    username = payload.get('sub')
    role = payload.get('role', 'guest')
    if not username:
        raise HTTPException(status_code=401, detail='Invalid token payload')
    return {'username': username, 'role': role}


def require_permission(permission: str):
    def dependency(current_user=Depends(get_current_user)):
        role = current_user['role']
        permissions = ROLE_PERMISSIONS.get(role, set())
        if permission not in permissions:
            raise HTTPException(status_code=403, detail='Not enough permissions')
        return current_user

    return dependency


def verify_docs_user(credentials: HTTPBasicCredentials = Depends(security_basic)):
    docs_user = os.getenv('DOCS_USER', 'admin')
    docs_password = os.getenv('DOCS_PASSWORD', 'admin')
    valid_user = secrets.compare_digest(credentials.username, docs_user)
    valid_password = secrets.compare_digest(credentials.password, docs_password)
    if not (valid_user and valid_password):
        raise HTTPException(
            status_code=401,
            detail='Unauthorized',
            headers={'WWW-Authenticate': 'Basic'},
        )
    return credentials.username
