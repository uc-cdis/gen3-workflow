from sqlalchemy import Column, DateTime, String
from sqlalchemy.orm import declarative_base
from sqlalchemy.sql import func


Base = declarative_base()


class SystemKey(Base):
    __tablename__ = "system_key"

    key_id = Column(String, primary_key=True)
    key_secret = Column(String, nullable=False)
    user_id = Column(String, nullable=False)
    created_time = Column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
