from datetime import datetime, timedelta
from io import StringIO
from typing import Dict

import pandas as pd                      # pip install pandas
import requests                          # pip install requests
from fastapi import (
    Depends, FastAPI, HTTPException, Query, status
)
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr

app = FastAPI(title="User Auth API – fase 1.1")

db: Dict[str, Dict[str, str]] = {}     

API_URL = "https://economia.awesomeapi.com.br/json/last/USD-BRL,EUR-BRL"

# ---------- Configurações de segurança ----------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY  = "TROQUE-ESSA-CHAVE"
ALGORITHM   = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
security = HTTPBearer()                # valida header Bearer

# ---------- Esquemas ----------
class UserRegister(BaseModel):
    username: str
    email:   EmailStr
    password: str

class UserLogin(BaseModel):
    email:    EmailStr
    password: str

class TokenOut(BaseModel):
    jwt: str

# ---------- Helpers ----------
def hash_password(plain_pwd: str) -> str:
    return pwd_context.hash(plain_pwd)

def create_access_token(sub: str) -> str:
    exp = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = {"sub": sub, "exp": exp}
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_password(plain_pwd: str, hashed_pwd: str) -> bool:
    return pwd_context.verify(plain_pwd, hashed_pwd)

def get_current_user(
    cred: HTTPAuthorizationCredentials = Depends(security),
) -> str:
    token = cred.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str | None = payload.get("sub")
        if email is None:
            raise JWTError()
    except JWTError:
        raise HTTPException(403, "Token inválido ou expirado")
    return email


# ---------- Endpoint /registrar ----------
@app.get("/", summary="Dump do banco em memória")
def show_db():
    # opcional: .copy() evita que alguém modifique o dicionário original
    return db.copy()

@app.post("/registrar", response_model=TokenOut, status_code=status.HTTP_201_CREATED)
def registrar(user: UserRegister):
    if user.email in db:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="E-mail já cadastrado",
        )

    db[user.email] = {
        "username": user.username,
        "email": user.email,
        "password": hash_password(user.password),
    }

    token = create_access_token(sub=user.email)
    return {"jwt": token}

@app.post("/login", response_model=TokenOut)
def login(credentials: UserLogin):
    stored = db.get(credentials.email)
    # 1. e-mail não encontrado  → 401
    if not stored:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="E-mail nao encontrado",
        )
    # 2. senha não confere      → 401
    if not verify_password(credentials.password, stored["password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Senha nao confere",
        )
    # 3. tudo ok → gera novo JWT e devolve
    token = create_access_token(sub=credentials.email)
    return {"jwt": token}

def fetch_fx_quotes() -> pd.DataFrame:
    """
    Consulta a AwesomeAPI e devolve DataFrame com USD/BRL e EUR/BRL.
    Campos principais: pair, bid, ask, high, low, pctChange, create_date
    """
    try:
        r = requests.get(API_URL, timeout=5)
        r.raise_for_status()
        data = r.json()                                   # ﹩USDBRL + ﹩EURBRL
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Erro ao consultar provedor externo: {exc}"
        )

    rows = []
    for pair in data.values():
        rows.append(
            {
                "pair":        f"{pair['code']}/{pair['codein']}",
                "bid":         float(pair["bid"]),
                "ask":         float(pair["ask"]),
                "high":        float(pair["high"]),
                "low":         float(pair["low"]),
                "pctChange":   float(pair["pctChange"]),
                "create_date": pair["create_date"],
            }
        )
    return pd.DataFrame(rows)

# ---------------------- Endpoint protegido ---------------------
@app.get("/consultar", summary="Cotação atual USD-BRL e EUR-BRL")
def consultar(
    formato: str = Query("json", enum=["json", "csv"]),
    _: str = Depends(get_current_user),
):
    df = fetch_fx_quotes()       # ⇐ agora usa a AwesomeAPI  :contentReference[oaicite:0]{index=0}

    if formato == "csv":
        csv_str = df.to_csv(index=False)
        return StreamingResponse(
            StringIO(csv_str),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=fx.csv"},
        )
    return JSONResponse(df.to_dict(orient="records"))