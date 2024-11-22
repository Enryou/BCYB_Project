# database.py

from sqlalchemy import create_engine, MetaData, Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import datetime
from databases import Database

# Define the SQLite database URL
DATABASE_URL = "sqlite:///./messages.db"

# Initialize the database instance from the databases package
database = Database(DATABASE_URL)

# Set up the database engine and metadata
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
metadata = MetaData()
Base = declarative_base()

# Define the User table using SQLAlchemy ORM
class User(Base):
    """
    This class represents the `users` table in the database.
    Each instance of the class corresponds to a row in the table.
    """
    __tablename__ = 'users'

    # Define columns of the table
    id = Column(Integer, primary_key=True, index=True)  # Primary key
    username = Column(String, unique=True, index=True)  # Unique username for the user
    hashed_password = Column(String)  # Hashed password for the user

# Define the messages table using SQLAlchemy ORM
class Message(Base):
    """
    This class represents the `messages` table in the database.
    Each instance of the class corresponds to a row in the table.
    """
    __tablename__ = 'messages'

    # Define columns of the table
    id = Column(Integer, primary_key=True, index=True)  # Primary key
    sender_id = Column(String, index=True)  # ID of the sender
    recipient_id = Column(String, index=True)  # ID of the recipient
    encrypted_message = Column(String)  # Encrypted message content
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)  # Timestamp of message creation

# Create the database tables
Base.metadata.create_all(bind=engine)

# Create a session factory to interact with the database
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Provide a dependency for the database session
def get_session():
    """
    Dependency to get a session for interacting with the database.
    Ensures that sessions are closed after use.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
