from typing import Optional
from fastapi import APIRouter, Header, Cookie, status
import jwt
from src.auth.router import pwd_context
from datetime import datetime, timezone
from src.users.schemas import CreateUserRequest, UserResponse, User
from src.common.database import blocked_token_db, session_db, user_db
from src.users.errors import (
    InvalidSession, 
    BadAuthorizationHeader, 
    InvalidToken, 
    UnauthenticatedExeption,
)

# JWT 설정
SECRET_KEY = "a2537d439a58e4b9f34e5e91fefd657b0044e1c2c4de5cf7c5fcea4d47c1a5bd"
ALGORITHM = "HS256"

user_router = APIRouter(prefix="/users", tags=["users"])

@user_router.post("/", status_code=status.HTTP_201_CREATED)
def create_user(request: CreateUserRequest) -> UserResponse:
    
    user_id = len(user_db) + 1
    
    user = User(
        user_id=user_id,
        email=request.email,
        hashed_password=pwd_context.hash(request.password),
        name=request.name,
        phone_number=request.phone_number,
        height=request.height,
        bio=request.bio
    )
    user_db.append(user)
    
    return UserResponse(
        user_id=user.user_id,
        email=user.email,
        name=user.name,
        phone_number=user.phone_number,
        height=user.height,
        bio=user.bio)

### 유저 조회 함수 ###
# user id로 user 조회 (공통)
def get_user_by_id(user_id: int) -> User | None:
    for user in user_db:
        if user.user_id == user_id:
            return user
    return None

#### 토큰 ####
# token 검증 (토큰)
def verify_token(token: str) -> int:
    if token in blocked_token_db:
        raise InvalidToken()
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if not user_id:
            raise InvalidToken()
        return int(user_id)
    except jwt.ExpiredSignatureError:
        raise InvalidToken()
    except jwt.InvalidTokenError:
        raise InvalidToken()
    
# token으로 user 조회 (토큰)
def get_user_from_token(authorization: str) -> User:
    if not authorization:
        raise UnauthenticatedExeption()
    
    if not authorization.startswith("Bearer "):
        raise BadAuthorizationHeader()
    token = authorization.split(" ")[1]
    user_id = verify_token(token)
    user = get_user_by_id(user_id)
    if not user:
        raise InvalidToken()
    return user

#### 세션 ####
# 세션 검증 (세션)
def verify_session(sid: str) -> int:
    if sid not in session_db:
        raise InvalidSession()
    
    user_id, expiry_time = session_db[sid]
    current_time = datetime.now(timezone.utc)

    if expiry_time < current_time:
        session_db.pop(sid)
        raise InvalidSession()
    return int(user_id)

# sid로 user 조회 (세션)
def get_user_from_session(sid: str) -> User:
    user_id = verify_session(sid)
    user = get_user_by_id(user_id)
    if not user:
        raise InvalidSession()
    return user

#정보 조회  
@user_router.get("/me", status_code=status.HTTP_200_OK)
def get_user_info(
    authorization: Optional[str] = Header(None),
    sid: Optional[str] = Cookie(None)
) -> UserResponse:
    
    # 세션 검사
    if sid:
        user = get_user_from_session(sid)
    
    # 토큰 검사
    elif authorization:
        user = get_user_from_token(authorization)
    # 둘 다 없는 경우
    else:
        raise UnauthenticatedExeption()
    
    return UserResponse(
        user_id=user.user_id,
        email=user.email,
        name=user.name,
        phone_number=user.phone_number,
        height=user.height,
        bio=user.bio
    )
    
