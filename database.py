from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base , sessionmaker

# conn_string = "host='localhost' dbname='TestDB' user='postgres' password='abcd'"
# conn = psycopg2.connect(conn_string)

engine = create_engine("postgresql://postgres:abcd@localhost:5432/pizza_delivery" , echo=True)
Base = declarative_base()

Session = sessionmaker()