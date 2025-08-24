from fastapi import APIRouter, Depends, HTTPException, Header
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
from database import get_db
from models import Users, RefreshToken
from datetime import datetime, timedelta, timezone
from schemas import UserCreate, UserRegister, TokenResponse, Login
from utils import AuthHandler, hash_password, verify_password, _token_hash, get_current_user  

import os, re, traceback


auth_router = APIRouter()

#######################################################
#################### 사용자 회원가입 ####################
#######################################################

@auth_router.post("/register", response_model=UserRegister)
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    try:
        # 이메일 검증
        if user.email:
            existing_user = db.query(Users).filter(Users.email == user.email).first()
            if existing_user:
                raise HTTPException(status_code=400, detail="이미 사용 중인 이메일입니다.")

        hashed_password = hash_password(user.password_hash)

        # 사용자 생성
        new_user = Users(
            username=user.username,
            email=user.email,
            password_hash=hashed_password,
            created_at=datetime.utcnow()
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        auth = AuthHandler()
        # 토큰 생성
        access_token = auth.create_access_token(new_user.user_id)
        refresh_token = auth.create_refresh_token(new_user.user_id)

        # 리프레시 토큰 저장 및 초기화 작업
        auth.save_token(db, new_user.user_id, refresh_token)
        db.commit()

        # 새 사용자 정보 갱신
        db.refresh(new_user)

        # 응답 반환
        return UserRegister(
            username=new_user.username,
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer"
            )

    # 데이터베이스 관련 오류 처리
    except SQLAlchemyError as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"데이터베이스 오류가 발생했습니다: {str(e)}")
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"예상치 못한 오류가 발생했습니다: {str(e)}")
    

#######################################################
##################### 사용자 로그인 #####################
#######################################################

@auth_router.post("/login", response_model=TokenResponse)
def login(data: Login, db: Session = Depends(get_db)):
    user = None
    identifier = data.identifier
    auth = AuthHandler()

    if identifier["type"] == "email":
        user = db.query(Users).filter(Users.email == identifier["value"]).first()

    if not user:
        raise HTTPException(status_code=404, detail="유저를 찾을 수 없습니다")
    

    if not verify_password(data.password,  user.password_hash):
        raise HTTPException(status_code=401, detail="비밀번호가 일치하지 않습니다")

    # 기존 유효 리프레시 폐기
    try:
        now = datetime.utcnow()
        db.query(RefreshToken).filter(
            RefreshToken.user_id == user.user_id,
            RefreshToken.revoked == False,
            RefreshToken.expires_at > now
        ).update({RefreshToken.revoked: True}, synchronize_session=False)

        # 새로운 액세스 토큰 및 리프레시 토큰 발급
        access_token = auth.create_access_token(user.user_id)
        refresh_token = auth.create_refresh_token(user.user_id)

    # 리프레시 토큰 저장
        auth.save_token(db, user.user_id, refresh_token)
        db.commit()
        return TokenResponse(access_token=access_token, refresh_token=refresh_token, token_type="bearer")
    except:
        db.rollback()
        raise

#######################################################
###################### 토큰 재발급 ######################
#######################################################
@auth_router.post("/refresh", response_model=TokenResponse)
def refresh(refresh_token: str = Header(None, alias="X-Refresh-Token"), db: Session = Depends(get_db)):
    if not refresh_token:
        raise HTTPException(status_code=400, detail="리프레시 토큰이 누락되었습니다.")

    auth = AuthHandler()
    try:
        # 1) 검증
        payload = auth.verify_refresh_token(db, refresh_token)
        user_id = int(payload["sub"])

        # 2) 회전
        new_access, new_refresh = auth.rotate_refresh_token(db, refresh_token, user_id)
        db.commit()
        return TokenResponse(access_token=new_access, refresh_token=new_refresh, token_type="bearer")
    except:
        db.rollback()
        raise

#######################################################
#######################  로그아웃 #######################
#######################################################

@auth_router.post("/logout")
def logout(refresh_token: str = Header(None, alias="X-Refresh-Token"), user: Users = Depends(get_current_user), db: Session = Depends(get_db)):
    
    if not refresh_token:
        raise HTTPException(400, "리프레시 토큰 누락")

    token_hash = _token_hash(refresh_token)
    refresh_token = db.query(RefreshToken).filter(
        RefreshToken.user_id == user.user_id,
        RefreshToken.token_hash == token_hash,
        RefreshToken.revoked == False,
    ).first()
    if not refresh_token:
        raise HTTPException(404, "리프레시 토큰을 찾을 수 없습니다")

    refresh_token.revoked = True
    db.commit() 
    return {"message": "현재 기기에서 로그아웃되었습니다"}