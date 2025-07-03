from sqlalchemy import Column, Sequence ,Integer, String, ForeignKey, create_engine
from sqlalchemy.orm import sessionmaker, relationship, declarative_base



engine = create_engine('sqlite:///orm.db', echo=True)

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

user = session.query(User).filter_by(name='John Doe').first()
print(user.name)

session.delete(user)
session.commit()