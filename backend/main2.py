# to run this main.py use : uvicorn main:app --host 0.0.0.0 --port 5000

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

from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- memcached Setup ---
# initializing memcache client for caching active chat sessions
mc = memcache.Client(['127.0.0.1:11211'], debug=0)
DB_PATH = "chat_history.db"

# --- initializing SQLite and Create Tables ---
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # table for storing chat history.
    # for authenticated users, user_id is the user's ID.
    # for guests, user_id is the guest's session ID.
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS chat_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT,
            role TEXT,
            message TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # table to store registered users
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            hashed_password TEXT
        )
    """)
    # table to track whether a chat session is active or ended and record the start of the current session
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS chat_session_status (
            user_id TEXT PRIMARY KEY,
            active BOOLEAN,
            session_start DATETIME,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

init_db()

# --- helper function for inserting/updating the chat session status ---
# so here we basically update or insert the session status for the given user_id (or guest session).
# here active=True means the chat is ongoing; active=False means the chat was ended
# if reactivating (active=True after being inactive), we update the session_start to the current time
def update_chat_session_status(user_id: str, active: bool):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    now_str = datetime.utcnow().isoformat(" ", "microseconds")
    cursor.execute("SELECT active, session_start FROM chat_session_status WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    if row:
        current_active = bool(row[0])
        if active and not current_active:
            # if reactivating, update active and session_start
            cursor.execute(
                "UPDATE chat_session_status SET active = ?, session_start = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?",
                (active, now_str, user_id)
            )
        else:
            # otherwise, just update the active status and updated_at
            cursor.execute(
                "UPDATE chat_session_status SET active = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?",
                (active, user_id)
            )
    else:
        # no record exists; if active, set session_start to now
        session_start = now_str if active else None
        cursor.execute(
            "INSERT INTO chat_session_status (user_id, active, session_start, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)",
            (user_id, active, session_start)
        )
    conn.commit()
    conn.close()


def get_chat_session_status(user_id: str) -> bool:
# if a record exists:
# it will return the actual active status stored in the record (either True or False)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT active FROM chat_session_status WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
# if no record exists (i.e., row is None):
# this means that no chat session status has been recorded for that user or session. 
# In such a case, the function returns True—indicating that the session is active.
    return True if row is None else bool(row[0])


# here we retrieve the session_start timestamp for the given user_id
# this timestamp marks the beginning of the current active session
def get_session_start(user_id: str) -> Optional[str]:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT session_start FROM chat_session_status WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return row[0]
    return None


SECRET_KEY = "generate-a-key-with-below-code"  

# import secrets
# def generate_secret_key(length=32):
#     return secrets.token_hex(length)
# secret_key = generate_secret_key()
# print("generated secret key:", secret_key)

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# hashing and verifying passwds
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
# using OAuth2 scheme for token authentication; auto_error=False returns None if no token is present.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login", auto_error=False)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

# creating a jwt token
def create_access_token(data: dict, expires_delta: Optional[timedelta]=None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt
  
# fetching user from db by username
def get_user(username: str):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, hashed_password FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return {"id": row[0], "username": row[1], "hashed_password": row[2]}
    return None

# authenticating a user by comparing the password with the hashed password in DB
def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user["hashed_password"]):
        return False
    return user

# optional authentication dependency that returns a user if a valid token is provided.
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


class UserCreate(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

# model for chat messages, it includes an optional session_id (for guest mode)
class ChatMessageRequest(BaseModel):
    message: str
    role: Optional[str] = "user"
    session_id: Optional[str] = None

# model for end chat request, for guest mode, session_id must be provided
class EndChatRequest(BaseModel):
    session_id: Optional[str] = None

# --- authentication endpoints ---

#  registering a new user, fir hash the password and store the user in the db
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


# login endpoint where a user is authenticated then a JWT token is returned
@app.post("/auth/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": user["username"]})
    return {"access_token": access_token, "token_type": "bearer"}

# --- chat functionality ---

# store a chat message permanently in SQLite with a high-precision timestamp (persistent storage)
def store_message_db(user_id: str, role: str, message: str):
    timestamp = datetime.utcnow().isoformat(" ", "microseconds")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # insert the message along with the generated timestamp
    cursor.execute(
        "INSERT INTO chat_history (user_id, role, message, timestamp) VALUES (?, ?, ?, ?)",
        (user_id, role, message, timestamp)
    )
    conn.commit()
    conn.close()

# adding a chat message to Memcached (for fast access) and persist in SQLite
def add_message(user_id: str, role: str, message: str):
    key = f"chat_{user_id}"
    chat_history = mc.get(key)
    if chat_history is None:
        chat_history = []
    chat_history.append({"role": role, "message": message})
    mc.set(key, chat_history, time=31536000)
    store_message_db(user_id, role, message)
    # whenever a message is added, the session is marked as active.
    update_chat_session_status(user_id, True)

# for guest mode, we use the same function
add_message_guest = add_message

# endpoint to handle incoming chat messages
# authenticated users: use user ID from token.
# for guests: session_id is provided
@app.post("/chat/message")
def chat_message(
    req: ChatMessageRequest, 
    current_user: Optional[dict] = Depends(get_optional_current_user)
):
    if current_user:
        user_id = str(current_user["id"])
        # reactivate session if ended by setting active to True and updating session_start
        update_chat_session_status(user_id, True)
        # the purpose of calling update_chat_session_status(user_id, True) is to "reactivate" the session when a new message is sent.
        # even for authenticated users, if they've previously ended the chat (which marks the session as inactive), sending a new message indicates that they are starting a new conversation. 
        # in that case, we want to mark the session as active again so that subsequent calls to fetch the chat history will return the updated messages.
        # in other words, for both guest and authenticated users, if a new message comes in—even after the chat was ended—we update the session status to active. 
        # this ensures that once a user (or guest) resumes chatting, their session is reactivated and messages are saved and retrieved normally.
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

# here we retrieve chat history.
# for authenticated users: only return messages from the current active session by filtering with session_start
# for guests: return messages for the session if active; if the session is ended, return an empty list
@app.get("/chat/history")
def chat_history(
    session_id: Optional[str] = Query(None, description="Session ID for guest mode"),
    current_user: Optional[dict] = Depends(get_optional_current_user)
):
    if current_user:
        user_id = str(current_user["id"])
        # if the session is marked as ended, return an empty history
        if not get_chat_session_status(user_id):
            return {"chat_history": []}
        key = f"chat_{user_id}"
        history = mc.get(key)
        if not history:
            # only fetch messages after the current session started
            session_start = get_session_start(user_id)
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            if session_start:
                cursor.execute("SELECT role, message FROM chat_history WHERE user_id = ? AND timestamp >= ? ORDER BY id ASC", (user_id, session_start))
            else:
                # if no session_start exists, fetch nothing.
                history = []
            rows = cursor.fetchall() if session_start else []
            history = [{"role": row[0], "message": row[1]} for row in rows]
            conn.close()
            mc.set(key, history, time=31536000)
        return {"chat_history": history}
    else:
        if not session_id:
            raise HTTPException(status_code=400, detail="session id required for guest mode")
        # do not reactivate session if it's ended; simply check and return empty if ended
        if not get_chat_session_status(session_id):
            return {"chat_history": []}
        key = f"chat_{session_id}"
        history = mc.get(key)
        if not history:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("select role, message from chat_history where user_id = ? order by id asc", (session_id,))
            rows = cursor.fetchall()
            history = [{"role": row[0], "message": row[1]} for row in rows]
            conn.close()
            mc.set(key, history, time=31536000)
        return {"chat_history": history}



    # here we end the chat session.
    # for authenticated users: clear the cache and mark the session as ended
    #  (this prevents old chat history from being shown on refresh)
    # for guest users: the session_id is taken from the request body; clear the cache and mark session as ended

@app.post("/chat/end")
def chat_end(req: Optional[EndChatRequest] = None, current_user: Optional[dict] = Depends(get_optional_current_user)):
    if current_user:
        user_id = str(current_user["id"])
        key = f"chat_{user_id}"
        mc.delete(key)
        # Mark the session as ended; new messages will start a fresh session.
        update_chat_session_status(user_id, False)
        return {"status": "Conversation ended; chat history will not be fetched."}
    else:
        session_id = req.session_id if req else None
        if not session_id:
            raise HTTPException(status_code=400, detail="Session ID required for guest mode")
        key = f"chat_{session_id}"
        mc.delete(key)
        update_chat_session_status(session_id, False)
        return {"status": "Guest conversation ended; chat history will not be fetched."}

if __name__ == '__main__':
    uvicorn.run(app, host="0.0.0.0", port=5000)
