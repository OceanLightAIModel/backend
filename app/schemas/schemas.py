from pydantic import BaseModel, Field, EmailStr, validator
from typing import Optional, List
from datetime import datetime
import re

## 사용자 회원가입 ##
class UserCreate(BaseModel):
    username: str = Field(..., description="사용자 이름")
    email: EmailStr = Field(..., description="사용자 이메일 주소")
    password_hash: str = Field(..., description="사용자 비밀번호 해시")

    class Config:
        from_attributes = True
    
    @validator("password_hash")
    def validate_password(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("비밀번호는 최소 8자 이상이어야 합니다.")
        if not re.search(r"[A-Z]", v):
            raise ValueError("비밀번호에는 최소 하나의 대문자가 포함되어야 합니다.")
        if not re.search(r"[0-9]", v):
            raise ValueError("비밀번호에는 최소 하나의 숫자가 포함되어야 합니다.")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", v):
            raise ValueError('비밀번호에는 특수문자가 포함되어야 합니다.')
        return v
    
    @validator("email")
    def validate_email(cls, v: str) -> str:
        if not v:
            raise ValueError("유효한 이메일 주소를 입력하세요.")
        return v
    
    ## 사용자 정보 조회 ##
class UserResponse(BaseModel):
    user_id: int = Field(..., description="사용자 ID")
    username: str = Field(..., description="사용자 이름")
    email: EmailStr = Field(..., description="사용자 이메일 주소")

    class Config:
        from_attributes = True
        orm_mode = True

    ## 사용자 회원가입 반환 ##
class UserRegister(BaseModel):
    username: str = Field(..., description="사용자 이름")
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    token_type: str = "bearer"

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class Login(BaseModel):
    identifier: str  
    password: str
    
    @validator("identifier")
    def validate_identifier(cls, v):
        email_regex = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
        if re.fullmatch(email_regex, v):
            return {"type": "email", "value": v}

        # 형식이 잘못된 경우 예외 발생
        raise ValueError("identifier는 유효한 이메일 또는 전화번호여야 합니다.")

