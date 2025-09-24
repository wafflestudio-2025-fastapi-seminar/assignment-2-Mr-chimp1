from pydantic import BaseModel, EmailStr, field_validator
from src.users.errors import MissingValueException, InvalidAccount, BadAuthorizationHeader, UnauthenticatedExeption
import re

class TokenData(BaseModel):
    email: EmailStr
    password: str

    @field_validator("email", "password")
    def check_missing(cls, v):
        if v is None or v == "":
            raise MissingValueException()
        return v

class ResponseToken(BaseModel):
    access_token: str
    refresh_token: str
    
class AuthorizationHeader(BaseModel):
    Authorization: str | None

    @field_validator("Authorization")
    def check_header(cls, v):
        if v is None:
            raise UnauthenticatedExeption()
        
        pattern = r"^Bearer\s[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.=]+$"
        if not re.fullmatch(pattern=pattern, string=v):
            raise BadAuthorizationHeader()
        return v
        
class SessionData(BaseModel):
    email: EmailStr
    password: str

    @field_validator("email", "password")
    def check_missing(cls, v):
        if v is None or v == "":
            raise MissingValueException()
        return v

class Cookies(BaseModel):
    session_id: str | None = None