from __future__ import annotations

import base64
import os
from datetime import datetime, timedelta
from typing import Optional

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Request,
    Response,
    status,
)
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext

from pydantic import BaseModel

# Configuration via env vars
SECRET_KEY = os.environ.get("DOCLING_SECRET_KEY", "change-me-in-prod")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("DOCLING_ACCESS_EXPIRE_MINUTES", "60"))

# Simple UI credentials (for Basic auth) — set these in your env for production
UI_USERNAME = os.environ.get("DOCLING_UI_USERNAME", "admin")
UI_PASSWORD = os.environ.get("DOCLING_UI_PASSWORD", "changeme")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

router = APIRouter(prefix="/auth", tags=["auth"])


class Token(BaseModel):
    access_token: str
    token_type: str


class User(BaseModel):
    username: str


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return pwd_context.verify(plain, hashed)
    except Exception:
        return plain == hashed


def get_user(username: str) -> Optional[dict]:
    # For now use env-backed single user. Replace with DB/LDAP in prod.
    if username == UI_USERNAME:
        # store hashed password in memory for verification
        # we don't persist the hashed value across runs; use hashed env var in prod
        return {"username": UI_USERNAME, "password": UI_PASSWORD}
    return None


def authenticate_user(username: str, password: str) -> Optional[User]:
    user = get_user(username)
    if not user:
        return None
    if not verify_password(password, user["password"]):
        return None
    return User(username=username)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


@router.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    access_token = create_access_token({"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}


async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user(username)
    if user is None:
        raise credentials_exception
    return User(username=username)


class BasicAuthMiddleware:
    """Simple Basic Auth middleware for protecting the Gradio UI path.

    If `DOCLING_UI_USERNAME` and `DOCLING_UI_PASSWORD` are not set,
    the middleware does nothing (UI remains public).
    """

    def __init__(self, app, username: str | None = None, password: str | None = None, path_prefix: str = "/ui"):
        self.app = app
        self.username = username
        self.password = password
        self.path_prefix = path_prefix

    async def __call__(self, scope, receive, send):
        # Only operate on HTTP requests
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if not path.startswith(self.path_prefix) or not self.username or not self.password:
            await self.app(scope, receive, send)
            return

        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        auth = headers.get("authorization")
        if not auth or not auth.startswith("Basic "):
            res = Response(status_code=401, content="Unauthorized")
            res.headers["WWW-Authenticate"] = "Basic realm=\"Docling UI\""
            await res(scope, receive, send)
            return

        try:
            b64 = auth.split(" ", 1)[1]
            decoded = base64.b64decode(b64).decode("utf-8")
            user, pw = decoded.split(":", 1)
        except Exception:
            res = Response(status_code=401, content="Unauthorized")
            res.headers["WWW-Authenticate"] = "Basic realm=\"Docling UI\""
            await res(scope, receive, send)
            return

        if user != self.username or pw != self.password:
            res = Response(status_code=403, content="Forbidden")
            await res(scope, receive, send)
            return

        await self.app(scope, receive, send)
