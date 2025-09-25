from pydantic import BaseModel, EmailStr, model_validator
from src.users.errors import MissingValueException

### 토큰 ###
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

### 세션 ###
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
