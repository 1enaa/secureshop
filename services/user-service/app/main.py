from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
import jwt, bcrypt, os
from datetime import datetime, timedelta

app = FastAPI(title="User Service", version="1.0.0")
security = HTTPBearer()

JWT_SECRET    = os.getenv("JWT_SECRET", "changeme-in-production")
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_H  = 24

users_db: dict = {}

class RegisterRequest(BaseModel):
    username: str
    email: EmailStr
    password: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

def create_token(user_id: str, email: str) -> str:
    return jwt.encode(
        {"sub": user_id, "email": email,
         "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRY_H),
         "iat": datetime.utcnow()},
        JWT_SECRET, algorithm=JWT_ALGORITHM
    )

def verify_token(creds: HTTPAuthorizationCredentials = Depends(security)):
    try:
        return jwt.decode(creds.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Invalid token")

@app.get("/health")
def health(): return {"status": "ok", "service": "user-service"}

@app.post("/register", status_code=201)
def register(body: RegisterRequest):
    if body.email in users_db:
        raise HTTPException(409, "Email already registered")
    hashed = bcrypt.hashpw(body.password.encode(), bcrypt.gensalt()).decode()
    uid = str(len(users_db) + 1)
    users_db[body.email] = {"id": uid, "username": body.username, "password": hashed}
    return {"message": "User registered", "user_id": uid}

@app.post("/login")
def login(body: LoginRequest):
    user = users_db.get(body.email)
    if not user or not bcrypt.checkpw(body.password.encode(), user["password"].encode()):
        raise HTTPException(401, "Invalid credentials")
    return {"access_token": create_token(user["id"], body.email), "token_type": "bearer"}

@app.get("/profile")
def profile(payload: dict = Depends(verify_token)):
    return {"user_id": payload["sub"], "email": payload["email"]}
