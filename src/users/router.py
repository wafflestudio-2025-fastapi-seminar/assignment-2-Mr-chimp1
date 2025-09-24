from typing import Annotated
from datetime import datetime, timezone
from fastapi.security import OAuth2PasswordBearer
from fastapi import (
    APIRouter,
    Depends,
    Cookie,
    Header,
    status
)

from src.users.schemas import CreateUserRequest, UserResponse, User
from src.common.database import blocked_token_db, session_db, user_db
from src.users.errors import InvalidSession, BadAuthorizationHeader, InvalidToken, UnauthenticatedExeption

import jwt

SECRET_KEY = "a2537d439a58e4b9f34e5e91fefd657b0044e1c2c4de5cf7c5fcea4d47c1a5bd"
ALGORITHM = "HS256"

user_router = APIRouter(prefix="/users", tags=["users"])

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')

@user_router.post("/", status_code=status.HTTP_201_CREATED)
def create_user(request: CreateUserRequest) -> UserResponse:
    from src.auth.router import pwd_context
    
    user_id = len(user_db) + 1
    
    # Create User object with hashed password
    user_data = {
        "user_id": user_id,
        "email": request.email,
        "hashed_password": pwd_context.hash(request.password),
        "name": request.name,
        "phone_number": request.phone_number,
        "height": request.height,
        "bio": request.bio
    }
    
    user = User(**user_data)
    user_db.append(user)
    
    # Create UserResponse without sensitive data
    return UserResponse(
        user_id=user.user_id,
        name=user.name,
        email=user.email,
        phone_number=user.phone_number,
        bio=user.bio,
        height=user.height
    )


def get_user_by_id(user_id: int) -> User | None:
    for user_info in user_db:
        if user_info.user_id == user_id:
            return user_info
    return None


@user_router.get("/me", response_model=UserResponse)
def get_user_info(
    authorization: str | None = Header(None, description="Bearer Token"), 
    sid: str | None = Cookie(None, description="Session_ID")
):
    # 토큰 기반 인증
    if authorization:
        # Authorization 헤더 형식 검증 (Bearer access_token)
        parts = authorization.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise BadAuthorizationHeader()
        
        token = parts[1]
        try:
            # 토큰 검증: 위조/변조 및 만료 검사
            payload = jwt.decode(
                token, 
                SECRET_KEY, 
                algorithms=[ALGORITHM],
                options={"verify_signature": True, "verify_exp": True}
            )
            
            # 토큰이 블록리스트에 있는지 확인
            if token in blocked_token_db:
                raise InvalidToken()
            
            user_id = payload.get("sub")
            if user_id is None:
                raise InvalidToken()
            
            user_id = int(user_id)
            user = get_user_by_id(user_id)
            if user is None:
                raise InvalidToken()
                
        except jwt.ExpiredSignatureError:
            raise InvalidToken()
        except jwt.InvalidTokenError:
            raise InvalidToken()
    
    # 세션 기반 인증
    elif sid:
        # 세션 존재 여부 확인
        session_data = session_db.get(sid)
        if session_data is None:
            raise InvalidSession()
        
        # 세션 만료 확인
        if isinstance(session_data, dict) and session_data.get("expires_at"):
            expires_at = session_data["expires_at"]
            if isinstance(expires_at, datetime):
                if expires_at < datetime.now(timezone.utc):
                    del session_db[sid]
                    raise InvalidSession()
            user_id = session_data.get("user_id")
        else:
            user_id = session_data  # 이전 버전 호환성 유지
            
        if user_id is None:
            raise InvalidSession()
            
        user = get_user_by_id(user_id)
        if user is None:
            raise InvalidSession()
    
    # 인증 정보가 전혀 없는 경우
    else:
        raise UnauthenticatedExeption()
    
    # UserResponse 형식으로 응답 반환
    return UserResponse(
        user_id=user.user_id,
        name=user.name,
        email=user.email,
        phone_number=user.phone_number,
        bio=user.bio,
        height=user.height
    )


        
