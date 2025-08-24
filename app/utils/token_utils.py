from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session
from fastapi.security import APIKeyHeader
from dotenv import load_dotenv
from models import Users, RefreshToken
from datetime import datetime, timedelta, timezone
from schemas import UserCreate, UserRegister
from jwt import ExpiredSignatureError, InvalidTokenError
from .hash_utils import _token_hash
from database import get_db
import os,jwt

load_dotenv()
TOKEN_PEPPER = os.getenv("TOKEN_PEPPER")
## JWT 토큰 생성 ##

class AuthHandler:
    def __init__(self):
        self.secret_key = os.getenv("TOKEN_SECRET_KEY")
        self.algorithm = os.getenv("TOKEN_ALGORITHM")
        self.access_token_expire_minutes = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES"))
        self.refresh_token_expire_days = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS"))
        self.api_key_header = APIKeyHeader(name="Authorization")

    def encode_token(self, user_id: int, expires_delta: timedelta, token_type: str) -> str:
        now = datetime.utcnow()
        encode_payload ={
            'sub' : str(user_id),
            'iat' : int(now.timestamp()),
            'exp' : int((now + expires_delta).timestamp()),
            'type': token_type
        }
        return jwt.encode(encode_payload, self.secret_key, algorithm=self.algorithm)

    def decode_token(self, token: str, refresh: bool = False) -> dict:
        try:
            decode_payload= jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return decode_payload
        except ExpiredSignatureError:
            if refresh:
                decode_payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm], options={"verify_exp": False})
                return decode_payload
            else:
                raise HTTPException(status_code=401, detail="토큰이 만료되었습니다.")
        except InvalidTokenError:
            raise HTTPException(status_code=401, detail="유효하지 않은 토큰입니다.")
            
### 엑세스 토큰 생성 ###
    def create_access_token(self, user_id: int) -> str:
        return self.encode_token(user_id, timedelta(minutes=self.access_token_expire_minutes), token_type="access")

### 리프레시 토큰 생성 ###
    def create_refresh_token(self, user_id: int) -> str:
        return self.encode_token(user_id, timedelta(days=self.refresh_token_expire_days), token_type="refresh")

### 토큰 저장 ###
    def save_token(self, db: Session, user_id: int, token: str, expires_at: datetime | None= None):
        if expires_at is None:
            expires_at = datetime.utcnow() + timedelta(days=self.refresh_token_expire_days)
        token_hash = _token_hash(token)
        refresh_token = RefreshToken(
            user_id=user_id,
            token_hash=token_hash,
            expires_at=expires_at,
            last_used_at=None,
            revoked=False,
            replaced_by=None
        )
        db.add(refresh_token)
        db.flush()
        return refresh_token
    
### 리프레시 토큰 검증 ###
    def verify_refresh_token(self, db: Session, token: str, *, expect_user_id: int | None = None) -> dict:
        payload = self.decode_token(token, refresh=True)
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="리프레시 토큰이 아닙니다.")

        token_hash = _token_hash(token)
        refresh_token = db.query(RefreshToken).filter(RefreshToken.token_hash == token_hash).first()
        if not refresh_token:
            raise HTTPException(status_code=401, detail="등록되지 않은 리프레시 토큰입니다.")

        # 소유자 확인
        sub = payload.get("sub")
        if sub is None or str(refresh_token.user_id) != str(sub):
            raise HTTPException(status_code=401, detail="토큰 소유자가 일치하지 않습니다.")
        if expect_user_id is not None and int(expect_user_id) != int(refresh_token.user_id):
            raise HTTPException(status_code=401, detail="요청 사용자와 토큰 소유자가 다릅니다.")

        now = datetime.utcnow()
        if refresh_token.expires_at <= now:
            raise HTTPException(status_code=401, detail="리프레시 토큰이 만료되었습니다.")
        if refresh_token.revoked:
            raise HTTPException(status_code=401, detail="무효화된 리프레시 토큰입니다.")
        if refresh_token.replaced_by:
            raise HTTPException(status_code=401, detail="이미 회전된 리프레시 토큰입니다.")

        return payload

### 리프레시 토큰 회전 ###
    def rotate_refresh_token(self, db: Session, old_token: str, user_id: int) -> tuple[str, str]:
        old_hash = _token_hash(old_token)
        refresh_token = (db.query(RefreshToken).with_for_update().filter_by(token_hash=old_hash, user_id=user_id).first())
        if not refresh_token or refresh_token.revoked:
            raise HTTPException(status_code=401, detail="회전할 리프레시 토큰이 유효하지 않습니다.")
        if refresh_token.replaced_by:
            raise HTTPException(status_code=401, detail="이미 회전된 리프레시 토큰입니다.")

            # 새 토큰 발급
        new_refresh = self.create_refresh_token(user_id)
        new_access = self.create_access_token(user_id)

        # 새 토큰 저장
        new_refresh_token = self.save_token(db, user_id, new_refresh)

        # 기존 토큰 폐기 + 연결
        refresh_token.revoked = True
        refresh_token.replaced_by = new_refresh_token.token_hash
        refresh_token.last_used_at = datetime.utcnow()
        return new_access, new_refresh
    

authorization = APIKeyHeader(name="Authorization", auto_error=False)
auth_handler = AuthHandler()
    
### 유저 조회 ###    
def get_current_user(bearer_token: str = Depends(authorization), db: Session = Depends(get_db)) -> Users:
    if not bearer_token:
        raise HTTPException(status_code=401, detail="인증 정보가 없습니다")
    if not bearer_token.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer 토큰이 필요합니다")

    token = bearer_token.split(" ", 1)[1]

    try:
        payload = auth_handler.decode_token(token) 
        if not payload:
            raise HTTPException(status_code=401, detail="토큰이 유효하지 않습니다")
        
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="액세스 토큰이 아닙니다")
        
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="토큰에 사용자 정보가 없습니다")

        user = db.query(Users).filter(Users.user_id == int(user_id)).first()
        if not user:
            raise HTTPException(status_code=404, detail="사용자를 찾을 수 없습니다")

        return user

    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="토큰이 만료되었습니다")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=403, detail=f"예상치 못한 오류: {str(e)}")
