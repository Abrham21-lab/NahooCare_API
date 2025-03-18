from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from models import User
from database import SessionLocal
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import jwt
import datetime
from typing import List
from fastapi.security import OAuth2PasswordBearer
# Secret key for JWT Token
SECRET_KEY = "your_secret_key"
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


ALGORITHM = "HS256"

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Replace with your frontend domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Password Hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Dependency to Get DB Session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Pydantic Models
class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str

class UserResponse(BaseModel):
    id: int
    username: str
    email: str

class UserUpdate(BaseModel):
    username: str
    email: str
    password:str

class UserCreate(BaseModel):
    username: str
    email:str
    password: str

    class Config:
        orm_mode = True

class UserResponse(BaseModel):
    message: str
    token: str
    user: dict

class UserListResponse(BaseModel):
    id: int
    username: str
    email: str    

        
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def generate_token(user: User) -> str:
    return create_access_token({"sub": user.username})

# ✅ JWT Token Generation
def create_access_token(data: dict, expires_delta: int = 60):
    expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=expires_delta)
    data.update({"exp": expire})
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

# ✅ User Registration
@app.post("/signup", response_model=UserResponse)
async def signup(user: UserCreate, db: Session = Depends(get_db)):
    print(user.dict())  # Debugging: See incoming data

    existing_user = db.query(User).filter(User.username == user.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already taken")

    new_user = User(username=user.username,email=user.email, password=hash_password(user.password))
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    token = generate_token(new_user)

    return {
        "message": "Signup successful",
        "token": token,
        "user": {"username": new_user.username}
    }


# ✅ User Login with Token Response
@app.post("/login")
def login(data: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == data.username.lower()).first()
    if not user or not pwd_context.verify(data.password, user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token({"sub": user.username})
    
    return {
        "message": "Login successful",
        "token": token,
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email
        }
    }


# ✅ Get All Users (For Debugging)
@app.get("/users", response_model=List[UserListResponse])
def get_users(db: Session = Depends(get_db)):
    return db.query(User).all()

@app.put("/update_user/{user_id}")
def update_user(user_id: int, user_update: UserUpdate, db: Session = Depends(get_db)):
    # Query the user by user_id
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Update the user's information
    user.username = user_update.username
    user.email = user_update.email
    db.commit()  # Commit the transaction to save the changes
    db.refresh(user)  # Refresh the user instance to reflect the changes

    return {"message": f"User with id {user_id} has been updated successfully", "updated_user": user}

@app.delete("/delete_user/{user_id}")
def delete_user(user_id: int, db: Session = Depends(get_db)):
    # Query the user by user_id
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    db.delete(user)  # Delete the user
    db.commit()  # Commit the transaction
    
    return {"message": f"User with id {user_id} has been deleted successfully"}

@app.get("/user")
def get_user_info(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        
    }

