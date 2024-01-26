from pydantic import BaseModel , validator , ValidationError , field_validator
# from pydantic import BaseModel as BaseSchema
# from pydantic import BaseSettings some people import this for settings of the jwt token
from pprintpp import pprint as pp
from typing import Optional
from datetime import date, datetime, time, timedelta
from models import User


class SignUpModel(BaseModel) : 
    id : Optional[int]  = 0
    username : str
    email : str
    password : str
    created_at : Optional[datetime] = datetime.utcnow()
    is_staff : Optional[bool] = False
    is_active : Optional[bool] = False


    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "username" : "johndoe" , 
                    "password" : "password" , 
                    "email" : "johndoe@gmail",
                    "is_staff" : False , 
                    "is_active" : True 
                }
            ]
        }
    }
        
class Settings(BaseModel) :
    SECRET_KEY : str = 'dd9ab4518374d959e38304faf35303c980246be9c6dec0fb17fa694f51d44d5c' 
    ALGORITHM : str =  "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES : int = 30



class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel) : 
    username : str

class OrderModel(BaseModel) : 
    id : Optional[int] = 0
    quantity : int
    order_status : Optional[str] = "PREPARING"
    pizza_size : Optional[str] = "SMALL"
    flavour_size : str
    user_id : Optional[int] = 0

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "quantity" : 2 , 
                    "pizza_size" : "LARGE" , 
                    "flavour_size" : "Pepperroni"
                }
            ]
        }
    }

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, 
            sort_keys=True, indent=4)

class BaseORMSchema(BaseModel):
    class Config:
        orm_mode = True