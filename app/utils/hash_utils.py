from passlib.context import CryptContext
from dotenv import load_dotenv
import os, hmac, hashlib

load_dotenv()
pepper = os.getenv("TOKEN_PEPPER")
if not pepper:
    raise RuntimeError("TOKEN_PEPPER is not set.")

## 비밀번호 해싱 설정 ##
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

## 비밀번호 해시화 ##
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

## 비밀번호 검증 ##
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


## 토큰 해쉬화 ##
def _token_hash(token: str) -> str:
    mac = hmac.new(pepper.encode("utf-8"), token.encode("utf-8"), hashlib.sha256)
    return mac.hexdigest() 