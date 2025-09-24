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

# 토큰 만료 시간 설정
SHORT_SESSION_LIFESPAN = 15  # Access Token 만료 시간 (분)
LONG_SESSION_LIFESPAN = 24 * 60  # Refresh Token 만료 시간 (분)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """비밀번호 검증"""
    return pwd_context.verify(plain_password, hashed_password)

def get_token_payload(token: str) -> dict:
    """토큰 검증 및 payload 반환"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise InvalidToken("Token has expired")
    except jwt.InvalidTokenError:
        raise InvalidToken("Invalid token")

def authenticate_user(email: str, password: str):
    """사용자 인증"""
    user = user_db.get(email)
    if not user or not verify_password(password, user['hashed_password']):
        raise InvalidAccount()
    return user

def create_token(data: dict, expires_delta: timedelta) -> str:
    """JWT 토큰 생성"""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_authorization_token(authorization: str) -> str:
    """Authorization 헤더에서 토큰 추출"""
    if not authorization or not authorization.startswith("Bearer "):
        raise BadAuthorizationHeader()
    return authorization.split(" ")[1]

def verify_and_get_payload(authorization: Optional[str] = Header(None)) -> TokenData:
    """토큰 검증 및 TokenData 반환"""
    if not authorization:
        raise UnauthenticatedExeption()
    
    token = get_authorization_token(authorization)
    
    # 블랙리스트 체크
    if token in blocked_token_db:
        raise InvalidToken("Token has been invalidated")
        
    payload = get_token_payload(token)
    return TokenData(sub=payload["sub"], exp=payload["exp"])

@auth_router.post("/token", response_model=ResponseToken, status_code=status.HTTP_201_CREATED)
def login_for_token(data: TokenData):
    """토큰 발급 엔드포인트"""
    user = authenticate_user(data.email, data.password)
    
    # access token 생성 (15분)
    access_token = create_token(
        data={"sub": str(user["user_id"])},
        expires_delta=timedelta(minutes=SHORT_SESSION_LIFESPAN)
    )
    
    # refresh token 생성 (24시간)
    refresh_token = create_token(
        data={"sub": str(user["user_id"])},
        expires_delta=timedelta(minutes=LONG_SESSION_LIFESPAN)
    )
    
    return ResponseToken(
        access_token=access_token,
        refresh_token=refresh_token
    )

@auth_router.post("/token/refresh", response_model=ResponseToken, status_code=status.HTTP_201_CREATED)
def refresh_token(authorization: Optional[str] = Header(None)):
    """토큰 갱신 엔드포인트"""
    if not authorization:
        raise UnauthenticatedExeption()
    
    token = get_authorization_token(authorization)
    
    # 블랙리스트 체크
    if token in blocked_token_db:
        raise InvalidToken("Token has been invalidated")
    
    # 토큰 검증
    payload = get_token_payload(token)
    user_id = payload.get("sub")
    if not user_id:
        raise InvalidToken("Invalid token payload")
        
    # 기존 refresh token을 블랙리스트에 추가
    blocked_token_db[token] = payload["exp"]
    
    # 새로운 토큰 쌍 생성
    access_token = create_token(
        data={"sub": user_id},
        expires_delta=timedelta(minutes=SHORT_SESSION_LIFESPAN)
    )
    
    refresh_token = create_token(
        data={"sub": user_id},
        expires_delta=timedelta(minutes=LONG_SESSION_LIFESPAN)
    )
    
    return ResponseToken(
        access_token=access_token,
        refresh_token=refresh_token
    )

@auth_router.delete("/token", status_code=status.HTTP_204_NO_CONTENT)
def logout(authorization: Optional[str] = Header(None)):
    """로그아웃 엔드포인트"""
    if not authorization:
        raise UnauthenticatedExeption()
    
    token = get_authorization_token(authorization)
    payload = get_token_payload(token)
    
    # 토큰을 블랙리스트에 추가
    blocked_token_db[token] = payload["exp"]
    
    return None

@auth_router.post("/session", status_code=status.HTTP_201_CREATED)
def session_login(response: Response, form_data: SessionData):
    """세션 로그인 엔드포인트"""
    # 사용자 검증
    user = authenticate_user(form_data.email, form_data.password)
    
    # 세션 ID 생성
    session_id = secrets.token_hex(32)
    
    # 세션 저장
    session_db[session_id] = str(user["user_id"])
    
    # 쿠키 설정
    response.set_cookie(
        key="sid",
        value=session_id,
        max_age=LONG_SESSION_LIFESPAN * 60,  # 분을 초로 변환
        httponly=True,
        samesite="lax"  # CSRF 보호
    )
    
    return {}

@auth_router.delete("/session", status_code=status.HTTP_204_NO_CONTENT)
def delete_session(response: Response, sid: Optional[str] = Cookie(None)):
    """세션 로그아웃 엔드포인트"""
    # 쿠키 만료
    response.delete_cookie(key="sid")
    
    # 세션이 존재하면 제거
    if sid and sid in session_db:
        session_db.pop(sid)
    
    return None