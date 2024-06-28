from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from database import engine, Base, get_db
from models import User as UserModel, Account
from schemas import UserCreate, User as UserSchema, Token, Login, AccountCreate, Transaction, Account as AccountSchema
from jose import JWTError, jwt
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import List

SECRET_KEY = "jlkjadasd"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

Base.metadata.create_all(bind=engine)

app = FastAPI()

def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict):
    to_encode = data.copy()
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

@app.post("/register", response_model=UserSchema)
def register(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(UserModel).filter(UserModel.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed_password = get_password_hash(user.password)
    db_user = UserModel(username=user.username, hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


@app.post("/token", response_model=Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

def authenticate_user(db, username: str, password: str):
    user = db.query(UserModel).filter(UserModel.username == username).first()
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def get_current_user(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(UserModel).filter(UserModel.username == username).first()
    if user is None:
        raise credentials_exception
    return user

@app.post("/account/add", response_model=AccountSchema)
def add_money(transaction: Transaction, db: Session = Depends(get_db), current_user: UserModel = Depends(get_current_user)):
    account = db.query(Account).filter(Account.user_id == current_user.id).first()
    if account is None:
        account = Account(user_id=current_user.id, balance=0)
        db.add(account)
    account.balance += transaction.amount
    db.commit()
    db.refresh(account)
    return account

@app.post("/account/remove", response_model=AccountSchema)
def remove_money(transaction: Transaction, db: Session = Depends(get_db), current_user: UserModel = Depends(get_current_user)):
    account = db.query(Account).filter(Account.user_id == current_user.id).first()
    if account is None or account.balance < transaction.amount:
        raise HTTPException(status_code=400, detail="Insufficient balance")
    account.balance -= transaction.amount
    db.commit()
    db.refresh(account)
    return account

@app.get("/account/balance", response_model=AccountSchema)
def get_balance(db: Session = Depends(get_db), current_user: UserModel = Depends(get_current_user)):
    account = db.query(Account).filter(Account.user_id == current_user.id).first()
    if account is None:
        raise HTTPException(status_code=400, detail="Account not found")
    return account

@app.get("/account/history", response_model=List[Transaction])
def get_history(db: Session = Depends(get_db), current_user: UserModel = Depends(get_current_user)):
    account = db.query(Account).filter(Account.user_id == current_user.id).first()
    if account is None:
        raise HTTPException(status_code=400, detail="Account not found")
    # Assuming you have a transaction history table, otherwise, keep transactions in memory or log
    transactions = db.query(Transaction).filter(Transaction.account_id == account.id).all()
    return transactions
