from pydantic import BaseModel, EmailStr, field_validator
from src.users.errors import MissingValueException, InvalidAccount, BadAuthorizationHeader, UnauthenticatedExeption
import re

class TokenData(BaseModel):
    email : EmailStr
    password : str

    @field_validator("email", "password")
    def check_missing(cls, v):
        if v == None:
            raise MissingValueException

class ResponseToken(BaseModel):
    access_token : str
    refresh_token : str
    
class AuthorizationHeader(BaseModel):
    Authorization : str | None

    @field_validator("Authorization")
    def check_header(cls, v):
        pattern = r"^Bearer\s[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.=]+$"
        if re.fullmatch(pattern=pattern, string = v):
            return v
        elif v == None:
            raise UnauthenticatedExeption
        else:
            raise BadAuthorizationHeader
        
class SessionData(BaseModel):
    email : EmailStr
    password : str

class Cookies(BaseModel):
    session_id: str