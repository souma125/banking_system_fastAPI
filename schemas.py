from pydantic import BaseModel
from typing import List

class UserCreate(BaseModel):
    username: str
    password: str

class User(BaseModel):
    id: int
    username: str

    class Config:
        from_attributes  = True

class Account(BaseModel):
    id: int
    balance: float

    class Config:
        from_attributes  = True

class AccountCreate(BaseModel):
    balance: float

class Transaction(BaseModel):
    amount: float

class Login(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str
