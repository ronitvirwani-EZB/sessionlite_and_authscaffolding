# import sqlite3
# import memcache
# from fastapi import FastAPI, HTTPException, Depends, Query
# from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
# from pydantic import BaseModel
# from typing import Optional
# from jose import JWTError, jwt
# from passlib.context import CryptContext
# from datetime import datetime, timedelta
# import uvicorn

# app = FastAPI()

# # --- CORS Middleware ---
# from fastapi.middleware.cors import CORSMiddleware
# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["*"],  # In production, restrict this to your domain
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )

# # --- Memcached Setup ---
# mc = memcache.Client(['127.0.0.1:11211'], debug=0)
# DB_PATH = "chat_history.db"

# # --- Initialize SQLite and Create Tables ---
# def init_db():
#     conn = sqlite3.connect(DB_PATH)
#     cursor = conn.cursor()
#     # Chat history: user_id can be either an authenticated user's ID or a guest's session_id.
#     cursor.execute("""
#         CREATE TABLE IF NOT EXISTS chat_history (
#             id INTEGER PRIMARY KEY AUTOINCREMENT,
#             user_id TEXT,
#             role TEXT,
#             message TEXT,
#             timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
#         )
#     """)
#     # Users table for authentication.
#     cursor.execute("""
#         CREATE TABLE IF NOT EXISTS users (
#             id INTEGER PRIMARY KEY AUTOINCREMENT,
#             username TEXT UNIQUE,
#             hashed_password TEXT
#         )
#     """)
#     conn.commit()
#     conn.close()

# init_db()

# # --- Security Settings ---
# SECRET_KEY = "your_secret_key_here"  # Replace with a secure key in production!
# ALGORITHM = "HS256"
# ACCESS_TOKEN_EXPIRE_MINUTES = 30

# pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
# # Set auto_error=False so that if no token is provided, the dependency returns None.
# oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login", auto_error=False)

# def verify_password(plain_password, hashed_password):
#     return pwd_context.verify(plain_password, hashed_password)

# def get_password_hash(password):
#     return pwd_context.hash(password)

# def create_access_token(data: dict, expires_delta: Optional[timedelta]=None):
#     to_encode = data.copy()
#     if expires_delta:
#         expire = datetime.utcnow() + expires_delta
#     else:
#         expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
#     to_encode.update({"exp": expire})
#     encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
#     return encoded_jwt

# def get_user(username: str):
#     conn = sqlite3.connect(DB_PATH)
#     cursor = conn.cursor()
#     cursor.execute("SELECT id, username, hashed_password FROM users WHERE username = ?", (username,))
#     row = cursor.fetchone()
#     conn.close()
#     if row:
#         return {"id": row[0], "username": row[1], "hashed_password": row[2]}
#     return None

# def authenticate_user(username: str, password: str):
#     user = get_user(username)
#     if not user:
#         return False
#     if not verify_password(password, user["hashed_password"]):
#         return False
#     return user

# # Optional authentication dependency.
# async def get_optional_current_user(token: str = Depends(oauth2_scheme)):
#     if not token:
#         return None
#     try:
#         payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
#         username: str = payload.get("sub")
#         if username is None:
#             return None
#     except JWTError:
#         return None
#     return get_user(username)

# # --- Pydantic Models ---
# class UserCreate(BaseModel):
#     username: str
#     password: str

# class Token(BaseModel):
#     access_token: str
#     token_type: str

# # Chat message request includes an optional session_id (for guest mode).
# class ChatMessageRequest(BaseModel):
#     message: str
#     role: Optional[str] = "user"
#     session_id: Optional[str] = None

# # End chat request: optional session_id for guest mode.
# class EndChatRequest(BaseModel):
#     session_id: Optional[str] = None

# # --- Auth Endpoints ---
# @app.post("/auth/register", response_model=Token)
# def register(user: UserCreate):
#     if get_user(user.username):
#         raise HTTPException(status_code=400, detail="Username already registered")
#     hashed_password = get_password_hash(user.password)
#     conn = sqlite3.connect(DB_PATH)
#     cursor = conn.cursor()
#     try:
#         cursor.execute("INSERT INTO users (username, hashed_password) VALUES (?, ?)",
#                        (user.username, hashed_password))
#         conn.commit()
#     except sqlite3.IntegrityError:
#         raise HTTPException(status_code=400, detail="Username already registered")
#     conn.close()
#     access_token = create_access_token(data={"sub": user.username})
#     return {"access_token": access_token, "token_type": "bearer"}

# @app.post("/auth/login", response_model=Token)
# def login(form_data: OAuth2PasswordRequestForm = Depends()):
#     user = authenticate_user(form_data.username, form_data.password)
#     if not user:
#         raise HTTPException(status_code=401, detail="Incorrect username or password")
#     access_token = create_access_token(data={"sub": user["username"]})
#     return {"access_token": access_token, "token_type": "bearer"}

# # --- Chat Functionality ---

# def store_message_db(user_id: str, role: str, message: str):
#     conn = sqlite3.connect(DB_PATH)
#     cursor = conn.cursor()
#     cursor.execute("INSERT INTO chat_history (user_id, role, message) VALUES (?, ?, ?)",
#                    (user_id, role, message))
#     conn.commit()
#     conn.close()

# def add_message(user_id: str, role: str, message: str):
#     key = f"chat_{user_id}"
#     chat_history = mc.get(key)
#     if chat_history is None:
#         chat_history = []
#     chat_history.append({"role": role, "message": message})
#     mc.set(key, chat_history, time=31536000)
#     store_message_db(user_id, role, message)

# # For guest mode, we use the same function.
# add_message_guest = add_message

# @app.post("/chat/message")
# def chat_message(req: ChatMessageRequest, current_user: Optional[dict] = Depends(get_optional_current_user)):
#     if current_user:
#         user_id = str(current_user["id"])
#         add_message(user_id, "user", req.message)
#         agent_response = f"Agent response to: {req.message}"
#         add_message(user_id, "agent", agent_response)
#         return {"response": agent_response}
#     else:
#         if not req.session_id:
#             raise HTTPException(status_code=400, detail="Session ID required for guest mode")
#         guest_session = req.session_id
#         add_message_guest(guest_session, "user", req.message)
#         agent_response = f"Agent response to: {req.message}"
#         add_message_guest(guest_session, "agent", agent_response)
#         return {"response": agent_response}

# @app.get("/chat/history")
# def chat_history(
#     session_id: Optional[str] = Query(None, description="Session ID for guest mode"),
#     current_user: Optional[dict] = Depends(get_optional_current_user)
# ):
#     if current_user:
#         user_id = str(current_user["id"])
#         key = f"chat_{user_id}"
#         history = mc.get(key)
#         if not history:
#             conn = sqlite3.connect(DB_PATH)
#             cursor = conn.cursor()
#             cursor.execute("SELECT role, message FROM chat_history WHERE user_id = ? ORDER BY id ASC", (user_id,))
#             rows = cursor.fetchall()
#             history = [{"role": row[0], "message": row[1]} for row in rows]
#             conn.close()
#             mc.set(key, history, time=31536000)
#         return {"chat_history": history}
#     else:
#         if not session_id:
#             raise HTTPException(status_code=400, detail="Session ID required for guest mode")
#         key = f"chat_{session_id}"
#         history = mc.get(key)
#         if not history:
#             conn = sqlite3.connect(DB_PATH)
#             cursor = conn.cursor()
#             cursor.execute("SELECT role, message FROM chat_history WHERE user_id = ? ORDER BY id ASC", (session_id,))
#             rows = cursor.fetchall()
#             history = [{"role": row[0], "message": row[1]} for row in rows]
#             conn.close()
#             mc.set(key, history, time=31536000)
#         return {"chat_history": history}

# # @app.post("/chat/end")
# # def chat_end(
# #     req: Optional[EndChatRequest] = None,
# #     session_id: Optional[str] = Query(None, description="Session ID for guest mode"),
# #     current_user: Optional[dict] = Depends(get_optional_current_user)
# # ):
# #     if current_user:
# #         user_id = str(current_user["id"])
# #         key = f"chat_{user_id}"
# #         mc.delete(key)
# #         return {"status": "Conversation ended, session cleared."}
# #     else:
# #         if not session_id:
# #             raise HTTPException(status_code=400, detail="Session ID required for guest mode")
# #         key = f"chat_{session_id}"
# #         mc.delete(key)
# #         return {"status": "Guest conversation ended, session cleared."}

# @app.post("/chat/end")
# def chat_end(
#     req: Optional[EndChatRequest] = None,
#     current_user: Optional[dict] = Depends(get_optional_current_user)
# ):
#     if current_user:
#         user_id = str(current_user["id"])
#         key = f"chat_{user_id}"
#         mc.delete(key)
#         return {"status": "Conversation ended, session cleared."}
#     else:
#         # Read session_id from the request body (req) for guest mode
#         session_id = req.session_id if req else None
#         if not session_id:
#             raise HTTPException(status_code=400, detail="Session ID required for guest mode")
#         key = f"chat_{session_id}"
#         mc.delete(key)
#         return {"status": "Guest conversation ended, session cleared."}

# if __name__ == '__main__':
#     uvicorn.run(app, host="0.0.0.0", port=5000)

# part2 guest histroy error 

# import sqlite3
# import memcache
# from fastapi import FastAPI, HTTPException, Depends, Query
# from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
# from pydantic import BaseModel
# from typing import Optional
# from jose import JWTError, jwt
# from passlib.context import CryptContext
# from datetime import datetime, timedelta
# import uvicorn

# app = FastAPI()

# # --- CORS Middleware ---
# from fastapi.middleware.cors import CORSMiddleware
# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["*"],  # In production, restrict allowed origins
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )

# # --- Memcached Setup ---
# mc = memcache.Client(['127.0.0.1:11211'], debug=0)
# DB_PATH = "chat_history.db"

# # --- Initialize SQLite and Create Tables ---
# def init_db():
#     conn = sqlite3.connect(DB_PATH)
#     cursor = conn.cursor()
#     # Table for chat history.
#     # For authenticated users, user_id is the user's ID.
#     # For guests, user_id is the guest's session ID.
#     cursor.execute("""
#         CREATE TABLE IF NOT EXISTS chat_history (
#             id INTEGER PRIMARY KEY AUTOINCREMENT,
#             user_id TEXT,
#             role TEXT,
#             message TEXT,
#             timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
#         )
#     """)
#     # Table for users (for authentication)
#     cursor.execute("""
#         CREATE TABLE IF NOT EXISTS users (
#             id INTEGER PRIMARY KEY AUTOINCREMENT,
#             username TEXT UNIQUE,
#             hashed_password TEXT
#         )
#     """)
#     # Table to track chat session status (active/inactive)
#     cursor.execute("""
#         CREATE TABLE IF NOT EXISTS chat_session_status (
#             user_id TEXT PRIMARY KEY,
#             active BOOLEAN,
#             updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
#         )
#     """)
#     conn.commit()
#     conn.close()

# init_db()

# # --- Helper Functions for Chat Session Status ---
# def update_chat_session_status(user_id: str, active: bool):
#     conn = sqlite3.connect(DB_PATH)
#     cursor = conn.cursor()
#     cursor.execute("SELECT * FROM chat_session_status WHERE user_id = ?", (user_id,))
#     row = cursor.fetchone()
#     if row:
#         cursor.execute(
#             "UPDATE chat_session_status SET active = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?",
#             (active, user_id)
#         )
#     else:
#         cursor.execute(
#             "INSERT INTO chat_session_status (user_id, active, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)",
#             (user_id, active)
#         )
#     conn.commit()
#     conn.close()

# def get_chat_session_status(user_id: str) -> bool:
#     conn = sqlite3.connect(DB_PATH)
#     cursor = conn.cursor()
#     cursor.execute("SELECT active FROM chat_session_status WHERE user_id = ?", (user_id,))
#     row = cursor.fetchone()
#     conn.close()
#     # If no record exists, we assume the session is active by default.
#     return True if row is None else bool(row[0])

# # --- Security Settings ---
# SECRET_KEY = "your_secret_key_here"  # Replace with a secure key in production!
# ALGORITHM = "HS256"
# ACCESS_TOKEN_EXPIRE_MINUTES = 30

# pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
# # Set auto_error=False so that if no token is provided, the dependency returns None.
# oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login", auto_error=False)

# def verify_password(plain_password, hashed_password):
#     return pwd_context.verify(plain_password, hashed_password)

# def get_password_hash(password):
#     return pwd_context.hash(password)

# def create_access_token(data: dict, expires_delta: Optional[timedelta]=None):
#     to_encode = data.copy()
#     if expires_delta:
#         expire = datetime.utcnow() + expires_delta
#     else:
#         expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
#     to_encode.update({"exp": expire})
#     encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
#     return encoded_jwt

# def get_user(username: str):
#     conn = sqlite3.connect(DB_PATH)
#     cursor = conn.cursor()
#     cursor.execute("SELECT id, username, hashed_password FROM users WHERE username = ?", (username,))
#     row = cursor.fetchone()
#     conn.close()
#     if row:
#         return {"id": row[0], "username": row[1], "hashed_password": row[2]}
#     return None

# def authenticate_user(username: str, password: str):
#     user = get_user(username)
#     if not user:
#         return False
#     if not verify_password(password, user["hashed_password"]):
#         return False
#     return user

# # Optional authentication dependency.
# async def get_optional_current_user(token: str = Depends(oauth2_scheme)):
#     if not token:
#         return None
#     try:
#         payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
#         username: str = payload.get("sub")
#         if username is None:
#             return None
#     except JWTError:
#         return None
#     return get_user(username)

# # --- Pydantic Models ---
# class UserCreate(BaseModel):
#     username: str
#     password: str

# class Token(BaseModel):
#     access_token: str
#     token_type: str

# # Chat message request includes an optional session_id (for guest mode).
# class ChatMessageRequest(BaseModel):
#     message: str
#     role: Optional[str] = "user"
#     session_id: Optional[str] = None

# # End chat request: optional session_id for guest mode.
# class EndChatRequest(BaseModel):
#     session_id: Optional[str] = None

# # --- Auth Endpoints ---
# @app.post("/auth/register", response_model=Token)
# def register(user: UserCreate):
#     if get_user(user.username):
#         raise HTTPException(status_code=400, detail="Username already registered")
#     hashed_password = get_password_hash(user.password)
#     conn = sqlite3.connect(DB_PATH)
#     cursor = conn.cursor()
#     try:
#         cursor.execute("INSERT INTO users (username, hashed_password) VALUES (?, ?)",
#                        (user.username, hashed_password))
#         conn.commit()
#     except sqlite3.IntegrityError:
#         raise HTTPException(status_code=400, detail="Username already registered")
#     conn.close()
#     access_token = create_access_token(data={"sub": user.username})
#     return {"access_token": access_token, "token_type": "bearer"}

# @app.post("/auth/login", response_model=Token)
# def login(form_data: OAuth2PasswordRequestForm = Depends()):
#     user = authenticate_user(form_data.username, form_data.password)
#     if not user:
#         raise HTTPException(status_code=401, detail="Incorrect username or password")
#     access_token = create_access_token(data={"sub": user["username"]})
#     return {"access_token": access_token, "token_type": "bearer"}

# # --- Chat Functionality ---

# def store_message_db(user_id: str, role: str, message: str):
#     conn = sqlite3.connect(DB_PATH)
#     cursor = conn.cursor()
#     cursor.execute("INSERT INTO chat_history (user_id, role, message) VALUES (?, ?, ?)",
#                    (user_id, role, message))
#     conn.commit()
#     conn.close()

# def add_message(user_id: str, role: str, message: str):
#     key = f"chat_{user_id}"
#     chat_history = mc.get(key)
#     if chat_history is None:
#         chat_history = []
#     chat_history.append({"role": role, "message": message})
#     mc.set(key, chat_history, time=31536000)
#     store_message_db(user_id, role, message)
#     # Whenever a message is added, mark the session as active.
#     update_chat_session_status(user_id, True)

# # For guest mode, we use the same function.
# add_message_guest = add_message

# @app.post("/chat/message")
# def chat_message(
#     req: ChatMessageRequest, 
#     current_user: Optional[dict] = Depends(get_optional_current_user)
# ):
#     if current_user:
#         user_id = str(current_user["id"])
#         # Before adding a message, if chat session was ended, reinitialize it (active=True)
#         update_chat_session_status(user_id, True)
#         add_message(user_id, "user", req.message)
#         agent_response = f"Agent response to: {req.message}"
#         add_message(user_id, "agent", agent_response)
#         return {"response": agent_response}
#     else:
#         if not req.session_id:
#             raise HTTPException(status_code=400, detail="Session ID required for guest mode")
#         guest_session = req.session_id
#         update_chat_session_status(guest_session, True)
#         add_message_guest(guest_session, "user", req.message)
#         agent_response = f"Agent response to: {req.message}"
#         add_message_guest(guest_session, "agent", agent_response)
#         return {"response": agent_response}

# @app.get("/chat/history")
# def chat_history(
#     session_id: Optional[str] = Query(None, description="Session ID for guest mode"),
#     current_user: Optional[dict] = Depends(get_optional_current_user)
# ):
#     if current_user:
#         user_id = str(current_user["id"])
#         # Check session status: if chat has been ended, return empty history.
#         if not get_chat_session_status(user_id):
#             return {"chat_history": []}
#         key = f"chat_{user_id}"
#         history = mc.get(key)
#         if not history:
#             conn = sqlite3.connect(DB_PATH)
#             cursor = conn.cursor()
#             cursor.execute("SELECT role, message FROM chat_history WHERE user_id = ? ORDER BY id ASC", (user_id,))
#             rows = cursor.fetchall()
#             history = [{"role": row[0], "message": row[1]} for row in rows]
#             conn.close()
#             mc.set(key, history, time=31536000)
#         return {"chat_history": history}
#     else:
#         if not session_id:
#             raise HTTPException(status_code=400, detail="Session ID required for guest mode")
#         if not get_chat_session_status(session_id):
#             return {"chat_history": []}
#         key = f"chat_{session_id}"
#         history = mc.get(key)
#         if not history:
#             conn = sqlite3.connect(DB_PATH)
#             cursor = conn.cursor()
#             cursor.execute("SELECT role, message FROM chat_history WHERE user_id = ? ORDER BY id ASC", (session_id,))
#             rows = cursor.fetchall()
#             history = [{"role": row[0], "message": row[1]} for row in rows]
#             conn.close()
#             mc.set(key, history, time=31536000)
#         return {"chat_history": history}

# @app.post("/chat/end")
# def chat_end(
#     req: Optional[EndChatRequest] = None,
#     current_user: Optional[dict] = Depends(get_optional_current_user)
# ):
#     if current_user:
#         user_id = str(current_user["id"])
#         key = f"chat_{user_id}"
#         mc.delete(key)
#         # Mark the chat session as ended, so history is not fetched later.
#         update_chat_session_status(user_id, False)
#         return {"status": "Conversation ended; chat history will not be fetched."}
#     else:
#         # For guest mode, read session_id from the request body.
#         session_id = req.session_id if req else None
#         if not session_id:
#             raise HTTPException(status_code=400, detail="Session ID required for guest mode")
#         key = f"chat_{session_id}"
#         mc.delete(key)
#         update_chat_session_status(session_id, False)
#         return {"status": "Guest conversation ended; chat history will not be fetched."}

# if __name__ == '__main__':
#     uvicorn.run(app, host="0.0.0.0", port=5000)

import sqlite3
import memcache
from fastapi import FastAPI, HTTPException, Depends, Query
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
import uvicorn

app = FastAPI()

# --- CORS Middleware ---
from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict allowed origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Memcached Setup ---
mc = memcache.Client(['127.0.0.1:11211'], debug=0)
DB_PATH = "chat_history.db"

# --- Initialize SQLite and Create Tables ---
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # Table for chat history.
    # For authenticated users, user_id is the user's ID.
    # For guests, user_id is the guest's session ID.
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS chat_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT,
            role TEXT,
            message TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # Table for users (for authentication)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            hashed_password TEXT
        )
    """)
    # Table to track chat session status (active/inactive)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS chat_session_status (
            user_id TEXT PRIMARY KEY,
            active BOOLEAN,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

init_db()

# --- Helper Functions for Chat Session Status ---
def update_chat_session_status(user_id: str, active: bool):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM chat_session_status WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    if row:
        cursor.execute(
            "UPDATE chat_session_status SET active = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?",
            (active, user_id)
        )
    else:
        cursor.execute(
            "INSERT INTO chat_session_status (user_id, active, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)",
            (user_id, active)
        )
    conn.commit()
    conn.close()

def get_chat_session_status(user_id: str) -> bool:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT active FROM chat_session_status WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    # If no record exists, we assume the session is active by default.
    return True if row is None else bool(row[0])

# --- Security Settings ---
SECRET_KEY = "your_secret_key_here"  # Replace with a secure key in production!
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
# Set auto_error=False so that if no token is provided, the dependency returns None.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login", auto_error=False)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta]=None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_user(username: str):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, hashed_password FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return {"id": row[0], "username": row[1], "hashed_password": row[2]}
    return None

def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user["hashed_password"]):
        return False
    return user

# Optional authentication dependency.
async def get_optional_current_user(token: str = Depends(oauth2_scheme)):
    if not token:
        return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            return None
    except JWTError:
        return None
    return get_user(username)

# --- Pydantic Models ---
class UserCreate(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

# Chat message request includes an optional session_id (for guest mode).
class ChatMessageRequest(BaseModel):
    message: str
    role: Optional[str] = "user"
    session_id: Optional[str] = None

# End chat request: optional session_id for guest mode.
class EndChatRequest(BaseModel):
    session_id: Optional[str] = None

# --- Auth Endpoints ---
@app.post("/auth/register", response_model=Token)
def register(user: UserCreate):
    if get_user(user.username):
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed_password = get_password_hash(user.password)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (username, hashed_password) VALUES (?, ?)",
                       (user.username, hashed_password))
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Username already registered")
    conn.close()
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/auth/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": user["username"]})
    return {"access_token": access_token, "token_type": "bearer"}

# --- Chat Functionality ---

def store_message_db(user_id: str, role: str, message: str):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO chat_history (user_id, role, message) VALUES (?, ?, ?)",
                   (user_id, role, message))
    conn.commit()
    conn.close()

def add_message(user_id: str, role: str, message: str):
    key = f"chat_{user_id}"
    chat_history = mc.get(key)
    if chat_history is None:
        chat_history = []
    chat_history.append({"role": role, "message": message})
    mc.set(key, chat_history, time=31536000)
    store_message_db(user_id, role, message)
    # Whenever a message is added, mark the session as active.
    update_chat_session_status(user_id, True)

# For guest mode, we use the same function.
add_message_guest = add_message

@app.post("/chat/message")
def chat_message(
    req: ChatMessageRequest, 
    current_user: Optional[dict] = Depends(get_optional_current_user)
):
    if current_user:
        user_id = str(current_user["id"])
        # Before adding a message, if chat session was ended, reinitialize it (active=True)
        update_chat_session_status(user_id, True)
        add_message(user_id, "user", req.message)
        agent_response = f"Agent response to: {req.message}"
        add_message(user_id, "agent", agent_response)
        return {"response": agent_response}
    else:
        if not req.session_id:
            raise HTTPException(status_code=400, detail="Session ID required for guest mode")
        guest_session = req.session_id
        update_chat_session_status(guest_session, True)
        add_message_guest(guest_session, "user", req.message)
        agent_response = f"Agent response to: {req.message}"
        add_message_guest(guest_session, "agent", agent_response)
        return {"response": agent_response}

@app.get("/chat/history")
def chat_history(
    session_id: Optional[str] = Query(None, description="Session ID for guest mode"),
    current_user: Optional[dict] = Depends(get_optional_current_user)
):
    if current_user:
        user_id = str(current_user["id"])
        # Check session status: if chat has been ended, return empty history.
        if not get_chat_session_status(user_id):
            return {"chat_history": []}
        key = f"chat_{user_id}"
        history = mc.get(key)
        if not history:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT role, message FROM chat_history WHERE user_id = ? ORDER BY id ASC", (user_id,))
            rows = cursor.fetchall()
            history = [{"role": row[0], "message": row[1]} for row in rows]
            conn.close()
            mc.set(key, history, time=31536000)
        return {"chat_history": history}
    else:
        if not session_id:
            raise HTTPException(status_code=400, detail="Session ID required for guest mode")
        # Reactivate guest session if history exists in DB but session is marked ended.
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM chat_history WHERE user_id = ?", (session_id,))
        count = cursor.fetchone()[0]
        conn.close()
        if count > 0 and not get_chat_session_status(session_id):
            update_chat_session_status(session_id, True)
        # If session is still ended, return empty history.
        if not get_chat_session_status(session_id):
            return {"chat_history": []}
        key = f"chat_{session_id}"
        history = mc.get(key)
        if not history:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT role, message FROM chat_history WHERE user_id = ? ORDER BY id ASC", (session_id,))
            rows = cursor.fetchall()
            history = [{"role": row[0], "message": row[1]} for row in rows]
            conn.close()
            mc.set(key, history, time=31536000)
        return {"chat_history": history}

@app.post("/chat/end")
def chat_end(
    req: Optional[EndChatRequest] = None,
    current_user: Optional[dict] = Depends(get_optional_current_user)
):
    if current_user:
        user_id = str(current_user["id"])
        key = f"chat_{user_id}"
        mc.delete(key)
        # Mark the chat session as ended, so history is not fetched later.
        update_chat_session_status(user_id, False)
        return {"status": "Conversation ended; chat history will not be fetched."}
    else:
        # For guest mode, read session_id from the request body.
        session_id = req.session_id if req else None
        if not session_id:
            raise HTTPException(status_code=400, detail="Session ID required for guest mode")
        key = f"chat_{session_id}"
        mc.delete(key)
        update_chat_session_status(session_id, False)
        return {"status": "Guest conversation ended; chat history will not be fetched."}

if __name__ == '__main__':
    uvicorn.run(app, host="0.0.0.0", port=5000)
