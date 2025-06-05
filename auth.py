import os
import jwt
import hashlib
import json
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from pathlib import Path
from fastapi import HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

# Configuration
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-super-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440  # 24 hours

# User database file
USERS_DB = Path("/opt/vps-manager/users_db.json")

# Security
security = HTTPBearer()

class User(BaseModel):
    id: str
    username: str
    email: str
    role: str = "user"  # admin, user
    created_at: str
    last_login: Optional[str] = None

class UserInDB(User):
    password_hash: str

class CreateUserRequest(BaseModel):
    username: str
    email: str
    password: str
    role: str = "user"

class LoginRequest(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    token: str
    user: User

def hash_password(password: str) -> str:
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against hash"""
    return hash_password(plain_password) == hashed_password

def create_access_token(data: dict) -> str:
    """Create JWT access token"""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str) -> Optional[Dict[str, Any]]:
    """Verify JWT token"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.PyJWTError:
        return None

def load_users() -> Dict[str, UserInDB]:
    """Load users from database file"""
    if not USERS_DB.exists():
        return {}
    
    try:
        with open(USERS_DB, 'r') as f:
            users_data = json.load(f)
        return {k: UserInDB(**v) for k, v in users_data.items()}
    except Exception as e:
        print(f"Error loading users: {e}")
        return {}

def save_users(users: Dict[str, Any]):
    """Save users to database file"""
    try:
        USERS_DB.parent.mkdir(parents=True, exist_ok=True)
        with open(USERS_DB, 'w') as f:
            # Convert UserInDB objects to dict if needed
            users_data = {}
            for k, v in users.items():
                if isinstance(v, UserInDB):
                    users_data[k] = v.model_dump()
                else:
                    users_data[k] = v
            json.dump(users_data, f, indent=2)
    except Exception as e:
        print(f"Error saving users: {e}")

def create_user(user_data: CreateUserRequest) -> UserInDB:
    """Create a new user"""
    users = load_users()
    
    if user_data.username in users:
        raise ValueError(f"User {user_data.username} already exists")
    
    new_user = UserInDB(
        id=user_data.username,
        username=user_data.username,
        email=user_data.email,
        role=user_data.role,
        password_hash=hash_password(user_data.password),
        created_at=datetime.utcnow().isoformat(),
        last_login=None
    )
    
    users[user_data.username] = new_user
    save_users(users)
    return new_user

def authenticate_user(username: str, password: str) -> Optional[UserInDB]:
    """Authenticate user with username and password"""
    users = load_users()
    user = users.get(username)
    if not user:
        return None
    if not verify_password(password, user.password_hash):
        return None
    
    # Update last login
    user.last_login = datetime.utcnow().isoformat()
    users[username] = user
    save_users(users)
    
    return user

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> User:
    """Get current authenticated user"""
    token = credentials.credentials
    payload = verify_token(token)
    
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    username: str = payload.get("sub")
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    users = load_users()
    user = users.get(username)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return User(**user.model_dump())

def require_admin(current_user: User = Depends(get_current_user)) -> User:
    """Require admin role"""
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    return current_user

# Optional dependency for routes that work with or without auth
def get_current_user_optional(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> Optional[User]:
    """Get current user if authenticated, None otherwise"""
    if not credentials:
        return None
    
    try:
        return get_current_user(credentials)
    except HTTPException:
        return None
