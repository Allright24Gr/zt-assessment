from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from dotenv import load_dotenv
import os

load_dotenv()

# 기본값은 docker-compose.yml 의 데모 기본값과 일치시킨다 — .env 없이도 백엔드↔MySQL
# 자격이 어긋나지 않도록(무설정 제출본 실행 대응).
DB_HOST = os.environ.get("DB_HOST", "mysql")
DB_PORT = os.environ.get("DB_PORT", "3306")
DB_NAME = os.environ.get("DB_NAME", "zt_assessment")
DB_USER = os.environ.get("DB_USER", "zt_user")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "ztDemo1234")

DATABASE_URL = (
    f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}"
    f"@{DB_HOST}:{DB_PORT}/{DB_NAME}?charset=utf8mb4"
)

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
