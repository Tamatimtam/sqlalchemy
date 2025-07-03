from sqlalchemy import Column, Sequence, Integer, String, ForeignKey, create_engine
from sqlalchemy.orm import sessionmaker, relationship, declarative_base

# PostgreSQL connection string
# Format: postgresql://username:password@host:port/database_name
POSTGRESQL_DATABASE_URL = "postgresql://postgres:password@localhost:5432/orm_db"
SQLITE_DATABASE_URL = "sqlite:///orm.db"

engine = create_engine(POSTGRESQL_DATABASE_URL, echo=True)

Session = sessionmaker(bind=engine)
session = Session()

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, Sequence('user_id_seq'), primary_key=True)
    name = Column(String(50))
    email = Column(String(50), unique=True)

Base.metadata.create_all(engine)

user1 = User(name='John Doe', email='john.doe@example.com')
user2 = User(name='Jane Smith', email='jane.smith@example.com')

# Add users to session
session.add(user1)
session.add(user2)
session.commit()  # Commit the new users first

user = session.query(User).filter_by(name='John Doe').first()
print(user.name)

