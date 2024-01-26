from datetime import datetime, timedelta
from fastapi import APIRouter , status , Depends

from database import Session , engine
from schemas import SignUpModel , Settings , TokenData 
from models import User

from fastapi.exceptions import HTTPException
from werkzeug.security import generate_password_hash , check_password_hash
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from typing import Annotated
from jose import JWTError, jwt


auth_router = APIRouter(
    prefix = '/auth',
    tags=['auth']
)

session = Session(bind = engine)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

settings = Settings()

def get_user(token: Annotated[str, Depends(oauth2_scheme)]) : 
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )   

    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("subject")

        if username is None:
            raise credentials_exception
        
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    
    db_user = session.query(User).filter(User.username == token_data.username).first()
    if db_user is None:
        raise credentials_exception
    
    return db_user
    

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=15))

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm= settings.ALGORITHM)
    return encoded_jwt


@auth_router.get('/')
async def Hello() : 
    return {"message" : "Hello World!"}


@auth_router.post('/signup' , response_model=SignUpModel, status_code = status.HTTP_201_CREATED)
async def signup(user:SignUpModel) : 
    db_email = session.query(User).filter(User.email == user.email).first()

    if db_email is not None : 
        return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="user with email already exists")
    
    db_username = session.query(User).filter(User.username == user.username).first()

    if db_username is not None : 
        return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="user with username already exists")
        

    new_user = User(
        username = user.username , 
        email = user.email , 
        password = generate_password_hash(user.password),
        is_staff = user.is_staff , 
        is_active = user.is_active
    )

    session.add(new_user)
    session.commit()

    return new_user

@auth_router.post('/login' , status_code = status.HTTP_200_OK)
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]) : 
    db_user = session.query(User).filter(User.username == form_data.username).first()

    if db_user and check_password_hash( db_user.password , form_data.password) : 
        access_token_expires = timedelta(minutes= settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"subject": db_user.username}, expires_delta= access_token_expires
        )
        return {"access_token": access_token, "token_type": "bearer"}

    raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="valid username or password required",
            headers={"WWW-Authenticate": "Bearer"},
        )


@auth_router.get('/temp')
async def Hello(current_user: Annotated[User, Depends(get_user)]) : 
    return {"message" : "Hello World!" , "temp" : current_user}