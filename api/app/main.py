from datetime import datetime, timedelta, timezone
from io import StringIO
import os
import socket
from typing import Generator
import pandas as pd
import requests
from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from sqlalchemy import Column, String, Integer, create_engine, select
from sqlalchemy.exc import IntegrityError, NoResultFound
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

app = FastAPI(title="User Auth API")

API_URL = "https://economia.awesomeapi.com.br/json/last/USD-BRL,EUR-BRL"

# ------------------------------------------------------------------ #
# 1.  Configurações de segurança (mesmo que antes)
# ------------------------------------------------------------------ #
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 60))
ALGORITHM = "HS256"  

DB_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+psycopg2://postgres:postgres@localhost:5432/fastapi_demo",
)

engine = create_engine(DB_URL, echo=False)
SessionLocal: sessionmaker[Session] = sessionmaker(
    bind=engine, autoflush=False, autocommit=False
)

class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(80), nullable=False)
    email = Column(String(255), nullable=False, unique=True, index=True)
    hashed_password = Column(String(255), nullable=False)

# cria as tabelas se não existirem
Base.metadata.create_all(bind=engine)

# Dependência para obter/fechar sessão em cada request
def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ------------------------------------------------------------------ #
# 3.  Esquemas Pydantic (inalterados)
# ------------------------------------------------------------------ #
class UserRegister(BaseModel):
    username: str
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class TokenOut(BaseModel):
    jwt: str

# ------------------------------------------------------------------ #
# 4.  Helpers (mesmos de antes)
# ------------------------------------------------------------------ #
def hash_password(plain: str) -> str:
    return pwd_context.hash(plain)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def create_access_token(sub: str) -> str:
    exp = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode({"sub": sub, "exp": exp}, SECRET_KEY, algorithm=ALGORITHM)

def fetch_fx_quotes() -> dict:
    try:
        r = requests.get(API_URL, timeout=5)
        r.raise_for_status()
        return r.json()
    except Exception as exc:
        raise HTTPException(502, f"Erro ao consultar provedor externo: {exc}")

def get_current_user(
    cred: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
) -> User:
    if cred is None:
        raise HTTPException(403, "Token ausente")
    token = cred.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str | None = payload.get("sub")
        if email is None:
            raise JWTError()
    except JWTError:
        raise HTTPException(403, "Token inválido ou expirado")

    try:
        user = db.scalar(select(User).where(User.email == email))
        if user is None:
            raise NoResultFound
    except NoResultFound:
        raise HTTPException(403, "Usuário não encontrado")
    return user

# ------------------------------------------------------------------ #
# 5.  Endpoints
# ------------------------------------------------------------------ #

# 5.1 health-check aberto
@app.get("/health-check", status_code=200, summary="Liveness probe")
def health_check():
    return {
        "statusCode": 200,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "hostname": socket.gethostname(),
    }

# 5.2 dump de usuários (apenas para debug; remova em produção)
@app.get("/", summary="Dump de usuários")
def dump(db: Session = Depends(get_db)):
    users = db.scalars(select(User)).all()
    return [
        {
            "id": u.id,
            "username": u.username,
            "email": u.email,
            "hashed_password": u.hashed_password,
        }
        for u in users
    ]

# 5.3 registrar
@app.post("/registrar", response_model=TokenOut, status_code=201)
def registrar(user: UserRegister, db: Session = Depends(get_db)):
    new_u = User(
        username=user.username,
        email=user.email,
        hashed_password=hash_password(user.password),
    )
    db.add(new_u)
    try:
        db.commit()
        db.refresh(new_u)
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "E-mail já cadastrado")

    return {"jwt": create_access_token(new_u.email)}

# 5.4 login
@app.post("/login", response_model=TokenOut)
def login(credentials: UserLogin, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.email == credentials.email))
    if not user or not verify_password(credentials.password, user.hashed_password):
        raise HTTPException(401, "Credenciais inválidas")
    return {"jwt": create_access_token(user.email)}

# 5.5 rota protegida
@app.get("/consultar", summary="Cotação USD-BRL e EUR-BRL")
def consultar(
    formato: str = Query("json", enum=["json", "csv"]),
    _: User = Depends(get_current_user),
):
    data = fetch_fx_quotes()

    if formato == "csv":
        df = pd.DataFrame.from_dict(data, orient="index").reset_index(drop=True)
        return StreamingResponse(
            StringIO(df.to_csv(index=False)),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=fx.csv"},
        )

    return JSONResponse(data)
