from fastapi import APIRouter
from fastapi import Depends, Cookie, Response, status
##
import jwt
import secrets
from jwt.exceptions import InvalidTokenError
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordRequestForm
from datetime import datetime, timedelta, timezone
from src.auth.schemas import TokenData, ResponseToken, AuthorizationHeader, SessionData, Cookies
from src.users.errors import InvalidAccount, InvalidToken
# from starlette.middleware.sessions import SessionMiddleware

from src.common.database import blocked_token_db, session_db, user_db

auth_router = APIRouter(prefix="/auth", tags=["auth"])

SECRET_KEY = "a2537d439a58e4b9f34e5e91fefd657b0044e1c2c4de5cf7c5fcea4d47c1a5bd"
ALGORITHM = "HS256"

SHORT_SESSION_LIFESPAN = 15
LONG_SESSION_LIFESPAN = 24 * 60

pwd_context = CryptContext(schemes=['bcrypt'], deprecated = "auto")

def create_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + expires_delta

    to_encode.update({'exp': expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm= ALGORITHM)
    return encoded_jwt

def get_user(user_db, email):
    for user_info in user_db:
        if user_info.email == email:
            return user_info
        return None
        

def varify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_hashed_password(password):
    return pwd_context.hash(password)

def authenticate_user(user_db, email: str, password: str):
    user_info = get_user(user_db, email)
    if not user_info:
        return False
    if not varify_password(password, user_info.hashed_password):
        return False
    return user_info



@auth_router.post("/token")
def token_login(form_data: TokenData) -> ResponseToken:
    user_info = authenticate_user(user_db, form_data.email, form_data.password)
    
    if not user_info:
        raise InvalidAccount
    
    access_token = create_token(data = {'sub':user_info.user_id}, expires_delta=timedelta(minutes=SHORT_SESSION_LIFESPAN))
    refresh_token = create_token(data = {'sub':user_info.user_id}, expires_delta=timedelta(minutes=LONG_SESSION_LIFESPAN))

    return ResponseToken(access_token=access_token, refresh_token= refresh_token)


@auth_router.post("/token/refresh")
def refresh(header: AuthorizationHeader)->ResponseToken:
    refresh_token = header.Authorization.split()[1]
    for blocked in blocked_token_db:
        if refresh_token == blocked.keys():
            raise InvalidToken
        
    decoded = jwt.decode(refresh_token)
    old_token = {refresh_token:decoded.exp}
    blocked_token_db.append(old_token)

    new_access_token = create_token(data = {'sub':decoded.sub}, expires_delta=timedelta(minutes=SHORT_SESSION_LIFESPAN))
    new_refresh_token = create_token(data = {'sub':decoded.sub}, expires_delta=timedelta(minutes=LONG_SESSION_LIFESPAN))

    return ResponseToken(access_token=new_access_token, refresh_token= new_refresh_token)



@auth_router.delete("/token")
def delete_token(header: AuthorizationHeader):
    refresh_token = header.Authorization.split()[1]
    for blocked in blocked_token_db:
        if refresh_token == blocked.keys():
            raise InvalidToken
        
    decoded = jwt.decode(refresh_token)
    old_token = {refresh_token:decoded.exp}
    blocked_token_db.append(old_token)

    return

@auth_router.post("/session")
def session_login(response: Response, form_data: SessionData):
    user_info = authenticate_user(user_db, form_data.email, form_data.password)
    
    if not user_info:
        raise InvalidAccount
    ## create session id
    session_id = secrets.token_hex(32)
    session_db.session_id = user_info.user_id

    response.set_cookie(
        key="sid",
        value = session_id,
        max_age = LONG_SESSION_LIFESPAN,
    )
    return

@auth_router.delete("/session", status_code= status.HTTP_204_NO_CONTENT)
def delete_cookie(response: Response, cookies: Cookies = Cookie()):
    sid = cookies.sid
    if sid:
        session_db.pop(sid)
        response.delete_cookie(key = "sid")
    return