from fastapi import APIRouter, Depends, HTTPException, status, Response, Request
from sqlalchemy.orm import Session
from ..db.session import SessionLocal
from ..schemas.user import UserCreate, UserOut
from ..crud.user import create_user, verify_user_credentials, get_user_by_email, set_refresh_jti
from ..core.security import create_access_token, create_refresh_token
from ..core.config import settings
from jose import jwt, JWTError
from datetime import timedelta

router = APIRouter(prefix="/auth", tags=["auth"])

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.post("/register", response_model=UserOut)
def register(payload: UserCreate, db: Session = Depends(get_db)):
    if get_user_by_email(db, payload.email):
        raise HTTPException(status_code=400, detail="Email already registered")
    user = create_user(db, payload.email, payload.password)
    # send verification email here (placeholder)
    return user

@router.post("/login")
def login(payload: UserCreate, response: Response, db: Session = Depends(get_db)):
    user = verify_user_credentials(db, payload.email, payload.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    access_token, access_jti = create_access_token(sub=str(user.id))
    refresh_token, refresh_jti = create_refresh_token(sub=str(user.id))
    # save refresh_jti to DB to allow revocation
    set_refresh_jti(db, user, refresh_jti)
    # set refresh cookie (httpOnly)
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        samesite="strict",
        secure=False,  # set True in production (HTTPS)
        max_age=60*60*24*settings.REFRESH_TOKEN_EXPIRE_DAYS
    )
    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/refresh")
def refresh_token(request: Request, response: Response, db: Session = Depends(get_db)):
    refresh = request.cookies.get("refresh_token")
    if not refresh:
        raise HTTPException(status_code=401, detail="No refresh token")
    try:
        payload = jwt.decode(refresh, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        user_id = payload.get("sub")
        jti = payload.get("jti")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    user = db.query(__import__("..models.user", fromlist=["User"]).User).get(int(user_id))
    if not user or user.current_refresh_jti != jti:
        # token revoked / rotated
        raise HTTPException(status_code=401, detail="Refresh token invalid or rotated")
    # rotate refresh token
    new_access, _ = create_access_token(sub=str(user.id))
    new_refresh, new_jti = create_refresh_token(sub=str(user.id))
    set_refresh_jti(db, user, new_jti)
    response.set_cookie(
        key="refresh_token",
        value=new_refresh,
        httponly=True,
        samesite="strict",
        secure=False,
        max_age=60*60*24*settings.REFRESH_TOKEN_EXPIRE_DAYS
    )
    return {"access_token": new_access, "token_type": "bearer"}

@router.post("/logout")
def logout(response: Response, request: Request, db: Session = Depends(get_db)):
    refresh = request.cookies.get("refresh_token")
    if refresh:
        try:
            payload = jwt.decode(refresh, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
            user_id = payload.get("sub")
            user = db.query(__import__("..models.user", fromlist=["User"]).User).get(int(user_id))
            if user:
                user.current_refresh_jti = None
                db.add(user); db.commit()
        except Exception:
            pass
    # remove cookie
    response.delete_cookie("refresh_token")
    return {"msg": "logged out"}
