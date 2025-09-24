from typing import Annotated
from datetime import datetime, timezone
from fastapi.security import OAuth2PasswordBearer
from fastapi import (
    APIRouter,
    Depends,
    Cookie,
    Header,
    status,
    HTTPException
)

from src.users.schemas import CreateUserRequest, UserResponse, User
from src.common.database import blocked_token_db, session_db, user_db
from src.users.errors import (
    InvalidSession, 
    BadAuthorizationHeader, 
    InvalidToken, 
    UnauthenticatedExeption,
    MissingValueException,
    InvalidPasswordException,
    EmailAlreadyExists,
    InvalidPhoneNumberException,
    BioTooLongException
)

import jwt

SECRET_KEY = "a2537d439a58e4b9f34e5e91fefd657b0044e1c2c4de5cf7c5fcea4d47c1a5bd"
ALGORITHM = "HS256"

user_router = APIRouter(prefix="/users", tags=["users"])

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')

@user_router.post("/", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def create_user(request: CreateUserRequest) -> UserResponse:
    """새 사용자를 생성하는 엔드포인트"""
    try:
        from src.auth.router import pwd_context
        
        # 새 user_id 생성
        user_id = len(user_db) + 1
        
        # User 객체 생성
        user = User(
            user_id=user_id,
            email=request.email,
            hashed_password=pwd_context.hash(request.password),
            name=request.name,
            phone_number=request.phone_number,
            height=request.height,
            bio=request.bio
        )
        
        # user_db에 저장
        user_db.append(user)
        
        # UserResponse 형식으로 응답
        return UserResponse(
            user_id=user.user_id,
            name=user.name,
            email=user.email,
            phone_number=user.phone_number,
            bio=user.bio,
            height=user.height
        )
    except (MissingValueException, InvalidPasswordException,
            InvalidPhoneNumberException, BioTooLongException) as e:
        # 422 Unprocessable Entity 에러
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error_code": e.error_code,
                "error_msg": e.error_msg
            }
        ) from e
    except EmailAlreadyExists as e:
        # 409 Conflict 에러
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error_code": e.error_code,
                "error_msg": e.error_msg
            }
        ) from e
    except Exception as e:
        print(f"Error in create_user: {str(e)}")
        raise


def get_user_by_id(user_id: int) -> User | None:
    """user_id로 사용자를 찾는 헬퍼 함수"""
    for user in user_db:
        if user.user_id == user_id:
            return user
    return None


@user_router.get("/me", response_model=UserResponse, status_code=status.HTTP_200_OK)
def get_user_info(
    authorization: str | None = Header(None, description="Bearer Token"), 
    sid: str | None = Cookie(None, description="Session_ID")
):
    """사용자 프로필 조회 엔드포인트"""
    if not authorization and not sid:
        raise UnauthenticatedExeption()
    
    try:
        user = None
        # 토큰 기반 인증
        if authorization:
            # Authorization 헤더 형식 검증
            parts = authorization.split()
            if len(parts) != 2 or parts[0].lower() != "bearer":
                raise BadAuthorizationHeader()
            
            token = parts[1]
            
            # 토큰이 블록리스트에 있는지 확인
            if token in blocked_token_db:
                raise InvalidToken()
            
            try:
                # 토큰 검증
                payload = jwt.decode(
                    token, 
                    SECRET_KEY, 
                    algorithms=[ALGORITHM]
                )
            except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
                raise InvalidToken()
            
            user_id = payload.get("sub")
            if not user_id:
                raise InvalidToken()
                
            user = get_user_by_id(int(user_id))
            if not user:
                raise InvalidToken()
        
        # 세션 기반 인증
        elif sid:
            if sid not in session_db:
                raise InvalidSession()
            
            user_id = session_db[sid]
            user = get_user_by_id(int(user_id))
            if not user:
                raise InvalidSession()
        
        # 응답 생성
        return UserResponse(
            user_id=user.user_id,
            name=user.name,
            email=user.email,
            phone_number=user.phone_number,
            bio=user.bio,  # bio는 선택사항이지만 User 모델에서 이미 처리됨
            height=user.height
        )
            
    except (InvalidToken, InvalidSession, BadAuthorizationHeader, UnauthenticatedExeption):
        raise
    except Exception as e:
        print(f"Error in get_user_info: {str(e)}")
        raise
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


        
