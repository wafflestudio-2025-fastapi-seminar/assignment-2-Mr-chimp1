from typing import Optional
from fastapi import APIRouter, Header, status, Response, Cookie
import jwt
import secrets
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
from pydantic import BaseModel

from src.auth.schemas import TokenData, ResponseToken, SessionData, Cookies
from src.users.errors import (
    InvalidAccount, 
    InvalidToken, 
    BadAuthorizationHeader,
    UnauthenticatedExeption
)
from src.common.database import blocked_token_db, user_db, session_db

auth_router = APIRouter(prefix="/auth", tags=["auth"])

# JWT 설정
SECRET_KEY = "a2537d439a58e4b9f34e5e91fefd657b0044e1c2c4de5cf7c5fcea4d47c1a5bd"
ALGORITHM = "HS256"

# 토큰 만료 시간
SHORT_SESSION_LIFESPAN = 15  
LONG_SESSION_LIFESPAN = 24 * 60  

# 비밀번호 해싱 설정
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_token_payload(token: str) -> dict:
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    return payload

def authenticate_user(email: str, password: str):
    # 이메일로 사용자 조회
    for user in user_db:
        if user.email == email:
            # 비밀번호 검증
            if verify_password(password, user.hashed_password):
                return user
    raise InvalidAccount()

def create_token(data: dict, expires_delta: timedelta) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_authorization_token(authorization: str) -> str:
    if not authorization.startswith("Bearer "):
        raise BadAuthorizationHeader()
    token = authorization.split(" ")[1]
    print(token)
    return token

def verify_and_get_payload(authorization: Optional[str] = Header(None)) -> TokenData:
    if not authorization:
        raise UnauthenticatedExeption()
    
    token = get_authorization_token(authorization)
    
    # 블랙리스트 체크
    if token in blocked_token_db:
        raise InvalidToken()
        
    payload = get_token_payload(token)
    return TokenData(sub=payload["sub"], exp=payload["exp"])

@auth_router.post("/token",  status_code=status.HTTP_200_OK)
def login_for_token(data: TokenData) -> ResponseToken:
    user = authenticate_user(data.email, data.password)
    
    # access token
    access_token = create_token(
        data={"sub": str(user.user_id)},
        expires_delta=timedelta(minutes=SHORT_SESSION_LIFESPAN)
    )
    
    # refresh token
    refresh_token = create_token(
        data={"sub": str(user.user_id)},
        expires_delta=timedelta(minutes=LONG_SESSION_LIFESPAN)
    )
    
    return ResponseToken(access_token=access_token, refresh_token=refresh_token)
    
@auth_router.post("/token/refresh", status_code=status.HTTP_200_OK)
def make_refresh_token(authorization: Optional[str] = Header(None)) -> ResponseToken:
    print("Authorization header:", authorization)
    if not authorization:
        raise UnauthenticatedExeption()
    
    token = get_authorization_token(authorization)
    print(token)

    try:
        # Verify this is a valid JWT token
        payload = get_token_payload(token)
        
        # Verify required claims exist
        user_id = payload.get("sub")
        expiry = payload.get("exp")
        if not user_id or not expiry:
            raise InvalidToken()
        
        # Check if token is already blocked
        if token in blocked_token_db:
            raise InvalidToken()
        
        # Verify token expiration
        current_time = datetime.now(timezone.utc).timestamp()
        if expiry < current_time:
            raise InvalidToken()
            
        # Block the old refresh token
        blocked_token_db[token] = expiry

        # Generate new tokens
        access_token = create_token(
            data={"sub": user_id},
            expires_delta=timedelta(minutes=SHORT_SESSION_LIFESPAN)
        )
        
        refresh_token = create_token(
            data={"sub": user_id},
            expires_delta=timedelta(minutes=LONG_SESSION_LIFESPAN)
        )
        
        return ResponseToken(access_token=access_token, refresh_token=refresh_token)
        
    except jwt.InvalidTokenError:
        raise InvalidToken()

@auth_router.delete("/token", status_code=status.HTTP_204_NO_CONTENT)
def logout(authorization: Optional[str] = Header(None)):
    if not authorization:
        raise UnauthenticatedExeption()
    
    token = get_authorization_token(authorization)
    payload = get_token_payload(token)
    
    blocked_token_db[token] = payload["exp"]
    
    return None

@auth_router.post("/session", status_code=status.HTTP_200_OK)
def session_login(response: Response, form_data: SessionData):
    user = authenticate_user(form_data.email, form_data.password)
    
    session_id = secrets.token_hex(32)
    expiry_time = datetime.now(timezone.utc) + timedelta(minutes=LONG_SESSION_LIFESPAN)

    session_db[session_id] = (int(user.user_id), expiry_time)
    
    response.set_cookie(
        key="sid",
        value=session_id,
        max_age=LONG_SESSION_LIFESPAN * 60, 
        httponly=True,
        samesite="lax"
    )
    
    return None

@auth_router.delete("/session", status_code=status.HTTP_204_NO_CONTENT)
def delete_session(response: Response, sid: Optional[str] = Cookie(None)):
    response.delete_cookie(key="sid")
    
    if sid and sid in session_db:
        session_db.pop(sid)
    
    return None