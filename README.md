# project overview

this project is a chat application built with fastapi on the backend and react on the frontend. it supports two modes of use:

guest mode: users can chat immediately without registering or logging in; a unique session id stored in localstorage is used to track their conversation.

authenticated mode: users can register and log in, and their chat history is tied to their user account via a jwt token; their messages persist across devices and page refreshes.
the application also includes:

----------------------------------------------------------------------------
## the application also includes:

1. real-time chat functionality: messages are sent and received, with a simulated agent response.
2. data persistence: every message is stored in a sqlite database.
3. caching: active sessions are cached in memcached for fast retrieval.
4. session status management: a separate table keeps track of whether a chat session is active or ended, so that old sessions do not reappear after a user ends a chat.
5. end chat functionality: when a user (guest or authenticated) ends a chat, the session is marked as ended (and a new session id is generated for guests) so that previous chat history is not shown.

-----------------------------------------------------------------------------
## implementation history & updates

### 1. initial guest chat functionality

goal: allow any visitor to start chatting immediately.

what we did:
-  built endpoints to send and retrieve messages using a session id.
-  stored messages in the chat_history table (with columns: id, user_id, role, message, timestamp).
-  generated a guest session id in the frontend (using localstorage) and passed it with every request.

edge cases covered:
-  if no session id exists in localstorage, a new one is generated.
-  if the guest refreshes the page, the same session id is used so that chat history is maintained.

### 2. adding end conversation functionality

goal: allow a user to end the current chat session so that old messages are not shown when the page is refreshed.

what we did:
-  created a new table called chat_session_status with columns: user_id, active, session_start, updated_at.
-  when a chat is ended, we mark the session as inactive (active = false) instead of deleting the history from the database.
-  the /chat/history endpoint checks the session status; if the session is ended, it returns an empty list.

edge cases covered:
-  if a session is ended and then a new message is sent, the session is reactivated (for both guest and authenticated users).
-  for guest users, if the session is ended, the localstorage value is removed and a new session id is generated.

### 3. adding authentication

goal: enable users to register and log in, so their chat history is associated with their account.

what we did:
-  added /auth/register and /auth/login endpoints.
-  stored user data in the users table (columns: id, username, hashed_password).
-  implemented jwt token generation (using a secret key, algorithm, and expiry).
-  created an optional authentication dependency (get_optional_current_user) that returns a user if a valid token is present or none if not.
-  modified chat endpoints to use the user’s id (from the token) when available.

edge cases covered:
-  login errors (422 errors) were fixed by sending form data as urlencoded data.
-  if a user is authenticated, the guest session id is not used.
-  if a user logs out, the guest session id is cleared to avoid data mixing.
  
### 4. dual mode support (guest and authenticated)
   
goal: have the same chat endpoints support both modes.

what we did:
-  in the chat endpoints, we check if current_user (from the token) exists.
  -  if yes, we use the authenticated branch (using the user’s id).
  -  if no, we require a session_id (provided by the frontend) and use the guest branch.
-  ensured that the session status table works for both guest session ids and authenticated user ids.

edge cases covered:
-  if a guest’s session is marked as ended but there is history in the database, we “reactivate” the session so that on refresh, the chat history appears (unless the chat was explicitly ended).
-  if a user ends a chat, only messages from the new session (after reactivation) are shown.

### 5. session management & timestamp precision

goal: ensure that when a new session starts (after ending a chat), old messages are not mixed with new ones.

what we did:
-  added a session_start column in the chat_session_status table to record when the current session began.
-  modified store_message_db to generate a high-precision timestamp (with microseconds) so that comparing the message timestamp with session_start works correctly.
-  in /chat/history for authenticated users, we only fetch messages with a timestamp greater than or equal to the session_start of the current session.

edge cases covered:
-  if a user sends a message exactly at the boundary, using high-precision timestamps ensures proper ordering.
-  if no session_start exists (should not happen), the endpoint defaults to returning nothing for safety.

### 6. frontend enhancements

goal: provide a landing page, navbar, and always-visible chat widget.

what we did:
-  built components for landing page, navbar, login, and register.
-  ensured that the navbar shows login/register buttons when not authenticated, and logout when authenticated.
-  the chat widget is always visible at the bottom-right and supports both guest and authenticated modes.
-  on login, the guest session id is cleared from localstorage so that it doesn’t mix with authenticated chat history.

edge cases covered:
-  if the same browser is used by different users, clearing the guest session id prevents mixing guest data between users.
-  proper error handling is implemented for network issues and invalid requests.

### 7. production migration (future integration)

goal: prepare the system for production use with a different chat agent (using a knowledge base and openai api).

what we should do (conceptually):
-  refactor the agent response generation logic into a separate module (e.g., agent.py).
-  in the chat endpoint, replace the simulated response with a call to the new agent function that uses the knowledge base and openai api.

edge cases to consider:
-  ensuring that the openai api key is secured via environment variables.
-  handling errors from the openai api gracefully.
-  caching frequently requested responses to reduce api calls.
-  scaling the asynchronous calls if traffic increases.


## edge cases covered

1. guest session persistence:
if a guest does not explicitly end the chat, the session id in localstorage persists, ensuring that chat history is maintained on page refresh.

2. session reactivation:
if a session was previously ended (active=false) but there are messages in the database, the backend reactivates the session when a new message is sent (by updating session_start).

3. timestamp precision issues:
by generating timestamps with microsecond precision for both messages and session_start, we ensure that filtering in /chat/history works correctly.

4. mixing of session data:
when a user logs in, the guest session id is cleared from localstorage to prevent mixing guest and authenticated chat histories.

5. login form data errors:
login credentials are sent as urlencoded form data to avoid 422 errors.

6. caching issues:
memcached is used to improve performance, and if the cache is empty, the backend falls back to the sqlite database.

7. optional authentication:
the endpoints gracefully handle cases when no jwt token is provided by falling back to guest mode.

8. ending chat behavior:
when chat is ended, the session is marked as ended and subsequent history fetches return an empty list until a new session is started.
