from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from .database import SessionLocal
from .models import User
from .schemas import UserCreate, UserLogin, Token, UserProfile
from .auth import (
    hash_password,
    verify_password,
    create_access_token,
    get_current_user,
)


router = APIRouter()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.post("/signup", status_code=201)
def signup(user: UserCreate, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == user.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    new_user = User(
        email=user.email,
        hashed_password=hash_password(user.password)
    )
    db.add(new_user)
    db.commit()
    return {"message": "User created"}

@router.post("/login", response_model=Token)
def login(user: UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if not db_user or not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )

    token = create_access_token({"sub": db_user.email})
    return {"access_token": token}

@router.get("/getUser", response_model=UserProfile)
def get_profile(current_user: User = Depends(get_current_user)):
    return current_user
