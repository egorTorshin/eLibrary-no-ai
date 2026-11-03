from datetime import datetime, timedelta, timezone
from typing import Annotated

import jwt
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jwt.exceptions import InvalidTokenError, InvalidAudienceError
from pydantic import BaseModel

SECRET_KEY = "a7b926fae42979ef1508db631f16a13d19ec65106a74d71f92555be16f2cf089"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

class User(BaseModel):
    user_id: int
    oauth_id: int
    email: str | None = None
    username: str
    role_id: int = 1

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    user_id: int
    role_id: int

class Item(BaseModel):
    user_id: int
    role_id: int


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("user_id")
        role_id = payload.get("role_id")
        if user_id is None or role_id is None:
            raise credentials_exception
        token_data = TokenData(user_id=user_id, role_id=role_id)
    except InvalidTokenError:
        raise credentials_exception
    return token_data


async def require_admin(token_data: Annotated[TokenData, Depends(get_current_user)]):
    role_exception = HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="You should be admin",
    )
  
    if token_data.role_id == 2:
        return "OK"
    else:
        raise role_exception


@app.post("/debug/token")
async def auth_test(item: Item):
    access_token = create_access_token(item.model_dump())

    return access_token