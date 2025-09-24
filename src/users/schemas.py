import re

from pydantic import BaseModel, field_validator, EmailStr
from fastapi import HTTPException

from src.users.errors import MissingValueException, InvalidPasswordException, EmailAlreadyExists, InvalidPhoneNumberException, BioTooLongException
from src.common.database import user_db

class CreateUserRequest(BaseModel):
    name: str
    email: EmailStr
    password: str
    phone_number: str
    bio: str | None
    height: float

    @field_validator('name', 'email', 'password', 'phone_number', 'height')
    def check_missing(cls, v):
        if v is None:
            raise MissingValueException()
        return v

    @field_validator('email', mode='after')
    def check_db(cls, v):
        for user in user_db:
            if user.email == v:
                raise EmailAlreadyExists()
        return v

    @field_validator('password', mode='after')
    def validate_password(cls, v):
        if len(v) < 8 or len(v) > 20:
            raise InvalidPasswordException()
        return v
    
    @field_validator('phone_number', mode='after')
    def validate_phone_number(cls, v):
        pattern = r'^010-\d{4}-\d{4}$'
        if not re.fullmatch(pattern, v):
            raise InvalidPhoneNumberException()
        return v

    @field_validator('bio', mode='after')
    def validate_bio(cls, v):
        if v is not None and len(v) > 500:
            raise BioTooLongException()
        return v

class User(BaseModel):
    user_id: int
    email: EmailStr
    hashed_password: str
    name: str
    phone_number: str
    height: float
    bio: str | None


class UserResponse(BaseModel):
    user_id: int
    name: str
    email: EmailStr
    phone_number: str
    bio: str | None
    height: float