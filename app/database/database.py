from sqlalchemy import *
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from dotenv import load_dotenv
import os

load_dotenv(override=True)
user= os.getenv("OCEAN_USER")
password = os.getenv("OCEAN_DB_USER_PASSWORD")
host = os.getenv("OCEAN_DB_HOST")
port = os.getenv("OCEAN_DB_PORT")
database = os.getenv("OCEAN_DB")

DB_URL = f"mysql+mysqlconnector://{user}:{password}@{host}:{port}/{database}"

## DB CONNECTION ##

engine = create_engine(DB_URL, 
                       connect_args={"charset": "utf8"},
                       pool_pre_ping=True)
Session = sessionmaker(autocommit=False, autoflush=False, bind=engine)
base = declarative_base()

def get_db():
    db = Session()
    try:
        yield db
    finally:
        db.close()
    
try:
    print(DB_URL)
    with engine.connect() as connection:
        print("DB 연결 성공")
except Exception as e:
        print("DB 연결 실패", e)