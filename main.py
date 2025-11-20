import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field
from passlib.context import CryptContext
import jwt

from database import db, create_document, get_documents

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security / JWT setup
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# ===== Models =====
class SignupRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=80)
    email: EmailStr
    password: str = Field(..., min_length=6, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=6, max_length=128)


class AuthResponse(BaseModel):
    token: str
    user: dict


# ===== Helpers =====

def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# ===== Routes =====
@app.get("/")
def read_root():
    return {"message": "Hello from FastAPI Backend!"}


@app.get("/api/hello")
def hello():
    return {"message": "Hello from the backend API!"}


@app.get("/test")
def test_database():
    """Test endpoint to check if database is available and accessible"""
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }

    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = db.name if hasattr(db, 'name') else "✅ Connected"
            response["connection_status"] = "Connected"

            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"

    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    # Check environment variables
    response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"

    return response


@app.post("/auth/signup", response_model=AuthResponse)
def signup(payload: SignupRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")

    # Check if user exists
    existing = get_documents("user", {"email": payload.email.lower()}, limit=1)
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    user_doc = {
        "name": payload.name.strip(),
        "email": payload.email.lower(),
        "password_hash": hash_password(payload.password),
        "is_active": True,
        "role": "user",
    }

    user_id = create_document("user", user_doc)

    token = create_access_token({"sub": str(user_id), "email": user_doc["email"]})

    # Omit password_hash in response
    public_user = {
        "_id": user_id,
        "name": user_doc["name"],
        "email": user_doc["email"],
        "is_active": user_doc["is_active"],
        "role": user_doc["role"],
    }

    return {"token": token, "user": public_user}


@app.post("/auth/login", response_model=AuthResponse)
def login(payload: LoginRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")

    users = get_documents("user", {"email": payload.email.lower()}, limit=1)
    if not users:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    user = users[0]
    if not verify_password(payload.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = create_access_token({"sub": str(user.get("_id")), "email": user.get("email")})

    public_user = {
        "_id": str(user.get("_id")),
        "name": user.get("name"),
        "email": user.get("email"),
        "is_active": user.get("is_active", True),
        "role": user.get("role", "user"),
    }

    return {"token": token, "user": public_user}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
