from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

Base = declarative_base()
engine = create_engine("sqlite:///messages.db")
SessionLocal = sessionmaker(bind=engine)

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)
    public_key = Column(Text, nullable=False)

    def verify_password(self, password):
        return check_password_hash(self.password, password)

class Message(Base):
    __tablename__ = 'messages'
    id = Column(Integer, primary_key=True, index=True)
    sender = Column(String, nullable=False)
    recipient = Column(String, nullable=False)
    message = Column(Text, nullable=False)
    signature = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=datetime.now)

Base.metadata.create_all(engine)

def get_user(username):
    with SessionLocal() as session:
        return session.query(User).filter(User.username == username).first()

def create_user(username, password, public_key):
    with SessionLocal() as session:
        user = User(username=username, password=generate_password_hash(password), public_key=public_key)
        session.add(user)
        session.commit()

def create_message(sender, recipient, message, signature):
    with SessionLocal() as session:
        msg = Message(sender=sender, recipient=recipient, message=message, signature=signature)
        session.add(msg)
        session.commit()

def get_messages(recipient):
    with SessionLocal() as session:
        return session.query(Message).filter(Message.recipient == recipient).order_by(Message.timestamp).all()

def get_public_key(username):
    with SessionLocal() as session:
        user = session.query(User).filter(User.username == username).first()
        return user.public_key if user else None