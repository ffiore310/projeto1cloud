from datetime import datetime, timedelta, timezone
import socket
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

def fetch_fx_quotes() -> dict:
    """
    Consulta a AwesomeAPI e devolve o JSON original, sem qualquer alteração.
    """
    try:
        r = requests.get(API_URL, timeout=5)
        r.raise_for_status()
        return r.json()                       # <-- devolve como veio
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Erro ao consultar provedor externo: {exc}"
        )

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

# ---------------------- Endpoint protegido ---------------------
@app.get("/consultar", summary="Cotação atual USD-BRL e EUR-BRL")
def consultar(
    formato: str = Query("json", enum=["json", "csv"]),
    _: str = Depends(get_current_user),
):
    data = fetch_fx_quotes()             

    if formato == "csv":
        # transforma em DataFrame só na hora de gerar CSV
        df = pd.DataFrame.from_dict(data, orient="index").reset_index(drop=True)
        csv_str = df.to_csv(index=False)
        return StreamingResponse(
            StringIO(csv_str),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=fx.csv"},
        )

    # formato json → devolve o conteúdo sem mudanças
    return JSONResponse(data)


@app.get("/health-check", summary="Liveness probe", status_code=200)
def health_check():
    """
    Retorna 200 sempre, com timestamp UTC e hostname do contêiner/VM.
    Não exige autenticação.
    """
    return {
        "statusCode": 200,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "hostname": socket.gethostname(),
    }