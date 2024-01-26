from database import Base
from sqlalchemy import Column, Integer, String, DateTime , Text , Boolean , ForeignKey
import datetime
from sqlalchemy_utils.types import ChoiceType
from sqlalchemy.orm import relationship

class User(Base) : 
    __tablename__ = 'users'

    id = Column(Integer , primary_key=True)
    username = Column(String(25) , unique = True , nullable=False) 
    email = Column(String(100) , unique=True , nullable=False)
    password = Column(Text , nullable = True)
    created_at = Column(DateTime , default=datetime.datetime.utcnow)
    is_staff = Column(Boolean , default = False)
    is_active = Column(Boolean , default = False)

    orders = relationship('Order' , back_populates='user')

    def __repr__(self):
        return f"<User {self.username}"


class Order(Base) : 
    OrderChoices = (('PREPARING' , 'preparing' ) , 
                    ('OUT_FOR_DELIVERY' , 'out_for_deliver'),
                    ('DELIVERED' , 'delivered') 
                    )

    PizzaSizes = (('SMALL' , 'small') , 
                  ('MEDIUM' , 'medium'),
                  ('LARGE' , 'large'),
                  ('EXTRA-LARGE' , 'extra-large')
                  )

    __tablename__ = 'orders'

    id = Column(Integer , primary_key=True)
    quantity = Column(Integer , nullable= False)
    order_status = Column(ChoiceType(OrderChoices) , default="PREPARING")
    pizza_size = Column(ChoiceType(PizzaSizes) , default="SMALL")
    flavour_size = Column(String(50) , nullable=False)
    user_id = Column(Integer , ForeignKey('users.id'))

    user = relationship('User' , back_populates='orders')

    def __repr__(self):
        return f"<Order {self.id}>"


#observation : suppose a database is created but a column is not passed it still works 