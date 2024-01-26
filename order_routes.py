from fastapi import APIRouter , Depends , status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from models import User , Order 
from schemas import OrderModel , Settings , TokenData
from typing import Annotated
from jose import JWTError, jwt
from fastapi.exceptions import HTTPException
from fastapi.encoders import jsonable_encoder

from database import Session , engine

import json


session = Session(bind=engine)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

settings = Settings()

order_router = APIRouter(
    prefix='/order',
    tags=['order']
)

def get_order(token: Annotated[str, Depends(oauth2_scheme)]) : 
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
        
    except JWTError:
        raise credentials_exception

    return Order( quantity = 2 , flavour_size = "Pepperoni")


@order_router.get('/')
async def Hello() : 
    return {"message" : "Hello World!"}


# this is a demo authorized function
@order_router.get('/temp')
async def Hello(order: Annotated[Order, Depends(get_order)]) : 
    return {"message" : "Hello World!" , "order" : order}



@order_router.post('/order' , status_code = status.HTTP_201_CREATED )
async def place_order(order : OrderModel , token: Annotated[str, Depends(oauth2_scheme)]) : 
    
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )   

    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("subject")
        token_data = TokenData(username=username)

        if username is None:
            raise credentials_exception  
    except JWTError:
        raise credentials_exception

    db_user = session.query(User).filter(User.username == token_data.username).first()

    new_order = Order(
        quantity = order.quantity , 
        pizza_size = order.pizza_size , 
        flavour_size = order.flavour_size , 
        user_id = db_user.id
    )

    new_order.user = db_user

    session.add(new_order)
    session.commit()

    response={
        "pizza_size":new_order.pizza_size,
        "quantity":new_order.quantity,
        "id":new_order.id,
        "order_status":new_order.order_status,
        "user_id":new_order.user_id,
        "flavour":new_order.flavour_size
    }

    return jsonable_encoder(response)

# get all orders
@order_router.get('/listorder')
async def list_order(token: Annotated[str, Depends(oauth2_scheme)]) : 
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
    )   
    
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("subject")
        token_data = TokenData(username=username)

        if username is None:
            raise credentials_exception  
    except JWTError:
        raise credentials_exception
    
    db_user = session.query(User).filter(User.username == token_data.username).first()

    if db_user.is_staff : 
        orders =  session.query(Order).all()
        return jsonable_encoder(orders)

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Requires Admin Access : This is accesible only to SuperUsers",
    )   


# get specific order
@order_router.get('/listorder/{id}')
async def list_order(id : int , token: Annotated[str, Depends(oauth2_scheme)]) : 
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
    )   
    
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("subject")
        token_data = TokenData(username=username)

        if username is None:
            raise credentials_exception  
    except JWTError:
        raise credentials_exception
    
    db_user = session.query(User).filter(User.username == token_data.username).first()

    if db_user.is_staff : 
        orders = session.query(Order).filter(Order.id == id).first()
        return jsonable_encoder(orders)

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Requires Admin Access : This is accesible only to SuperUsers",
    )   
    
# get orders of the current user
@order_router.get('/user/orders')
async def list_user_orders(token: Annotated[str, Depends(oauth2_scheme)]) : 
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
    )   
    
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("subject")
        token_data = TokenData(username=username)

        if username is None:
            raise credentials_exception  
    except JWTError:
        raise credentials_exception
    
    db_user = session.query(User).filter(User.username == token_data.username).first()

    return jsonable_encoder(db_user.orders)

# get the order status of a an order of user 
@order_router.get('/user/orderstatus/{orderid}')
async def user_order(orderid : int , token: Annotated[str, Depends(oauth2_scheme)]) : 
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
    )   
    
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("subject")
        token_data = TokenData(username=username)

        if username is None:
            raise credentials_exception  
    except JWTError:
        raise credentials_exception
    
    db_user = session.query(User).filter(User.username == token_data.username).first()

    for curr_order in db_user.orders : 
        if curr_order.id == orderid : 
            return jsonable_encoder(curr_order)
    
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST , 
        detail="Invalid Order Id : Enter a valid order id form your orders",
    )   


@order_router.put('/update/{orderid}')
async def user_order(orderid : int, order : OrderModel, token: Annotated[str, Depends(oauth2_scheme)]) : 
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
    )   
    
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("subject")
        token_data = TokenData(username=username)

        if username is None:
            raise credentials_exception  
    except JWTError:
        raise credentials_exception
    
    db_order = session.query(Order).filter(Order.id == orderid).first()

    db_order.quantity = order.quantity
    db_order.pizza_size = order.pizza_size
    
    if(order.flavour_size) : 
        db_order.flavour_size = order.flavour_size
    
    session.commit()

    return jsonable_encoder(db_order)


@order_router.delete("/user/delete/{orderid}" , status_code = status.HTTP_204_NO_CONTENT)
async def delete_user_order(orderid : int , token : Annotated[str, Depends(oauth2_scheme)]) : 
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
    )   
    
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("subject")
        token_data = TokenData(username=username)

        if username is None:
            raise credentials_exception  
    except JWTError:
        raise credentials_exception
    
    db_order = session.query(Order).filter(Order.id == orderid).first()
    
    if db_order : 
        session.delete(db_order)
        session.commit()

    return jsonable_encoder(db_order)