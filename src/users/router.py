from typing import Annotated
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
    user_id = len(user_db) + 1
    user = request.model_dump()
    user["user_id"] = user_id
    user_db.append(user)
    response = user
    return response


def get_user_by_id(user_id: int) -> User | None:
    for user_info in user_db:
        if user_info.user_id == user_id:
            return user_info
    return None


@user_router.get("/me", response_model= UserResponse)
def get_user_info(authorization: str | None = Header(None, description= "Bearer Token"), 
                  sid: str | None = Cookie(None, description= "Session_ID")):
    
# 토큰 기반 인증
    if authorization:
        parts = authorization.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise BadAuthorizationHeader()
        
        token = parts[1]
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = int(payload.get("sub"))
        if user_id is None:
            raise InvalidToken()
        
        user = get_user_by_id(user_id)
        if user is None:
            raise InvalidToken()
        
# 세션 기반 인증
    elif sid:
        user_id = session_db.get(sid)
        if user_id is None:
            raise InvalidSession()
        
        user = get_user_by_id(user_id)
        if user is None: # 세션은 유효하나 해당 유저가 DB에 없는 경우
            raise InvalidSession()
    
    # 3. 인증 정보가 전혀 없는 경우
    else:
        raise UnauthenticatedExeption()
        
    return user


        
