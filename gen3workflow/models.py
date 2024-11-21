from sqlalchemy import Column, String
from sqlalchemy.orm import declarative_base


Base = declarative_base()


class SystemKey(Base):
    __tablename__ = "system_key"

    key_id = Column(String, primary_key=True)
    key_secret = Column(String)
    user_id = Column(String)
