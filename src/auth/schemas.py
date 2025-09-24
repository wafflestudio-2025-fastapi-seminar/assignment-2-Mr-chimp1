from pydantic import BaseModel, EmailStr, field_validator, model_validator
from src.users.errors import MissingValueException, InvalidAccount, BadAuthorizationHeader, UnauthenticatedExeption
import re

class TokenData(BaseModel):
    email: EmailStr
    password: str

    @model_validator(mode='before')
    def check_missing(cls, v):
        required_fields = ['email', 'password']

        for field in required_fields:
            if field not in v or not v[field]:
                raise MissingValueException()
        return v

class ResponseToken(BaseModel):
    access_token: str
    refresh_token: str
    
class AuthorizationHeader(BaseModel):
    Authorization: str | None

    @field_validator("Authorization", mode="after")
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

class SessionData(BaseModel):
    email: EmailStr
    password: str

    @model_validator(mode='before')
    def check_missing(cls, v):
        required_fields = ['email', 'password']
            
        for field in required_fields:
            if field not in v or not v[field]:
                raise MissingValueException()
        return v

class Cookies(BaseModel):
    session_id: str | None = None