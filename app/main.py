from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from database import get_db, engine, base
from models import base
from route.auth import auth_router


app = FastAPI()
app.include_router(auth_router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "https://your-frontend.com"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# base.metadata.create_all(bind=engine) DB 처음 생성할 때만 사용, DB 테이블이 이미 존재하면 오류 발생

@app.get("/")
def root():
    return {"message": "FastAPI + MySQL Docker 환경입니다!"}

