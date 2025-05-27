# Projeto 1 - Computação em Nuvem

API RESTful para cadastro, autenticação de usuários e consulta de cotações (USD-BRL, EUR-BRL).

---

## 🔧 Pré-requisitos

- Docker & Docker Compose  
- Conta no Docker Hub (usuário: `ffiore310`)  
- `.env` configurado (exemplo abaixo)

---

## 📁 Estrutura do projeto
├── api
│ ├── app
│ │ └── main.py
│ ├── Dockerfile
│ └── requirements.txt
├── .env
└── compose.yaml

---

## ⚙️ Variáveis de ambiente (`.env`)

```dotenv
# Postgres
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres
POSTGRES_DB=fastapi_demo
POSTGRES_PORT=5432

# Connection string
DATABASE_URL=postgresql+psycopg2://${POSTGRES_USER}:${POSTGRES_PASSWORD}@database:${POSTGRES_PORT}/${POSTGRES_DB}

# App
APP_PORT=8080
SECRET_KEY=<chave-secreta-jwt>
ACCESS_TOKEN_EXPIRE_MINUTES=60

# Docker image
IMAGE_NAME=ffiore310/projeto1cloud-app
IMAGE_TAG=latest

---

## Build e execução local

No diretório raiz, rode:
# 1. Build das imagens (API + Postgres)
docker compose -f compose.yaml build

# 2. Start em background
docker compose -f compose.yaml up -d

# 3. Verifique
docker compose -f compose.yaml ps
A API ficará disponível em http://localhost:8080
