
import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import './ChatWidget.css';

const ChatWidget = ({ token }) => {
  const [isOpen, setIsOpen] = useState(false);
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState("");
  // for guest mode, we manage a session ID in localStorage
  const [sessionId, setSessionId] = useState(null);
  const messagesEndRef = useRef(null);

  useEffect(() => {
    if (token) {
      // for authenticated mode we set the JWT token in axios headers
      axios.defaults.headers.common["Authorization"] = `Bearer ${token}`;
      fetchChatHistoryAuth();
    } else {
      // for guest mode we retrieve or generate a unique session ID
      let session = localStorage.getItem("chat_session_id");
      if (!session) {
        session = "session-" + Math.random().toString(36).substr(2, 9);
        localStorage.setItem("chat_session_id", session);
      }
      setSessionId(session);
      fetchChatHistoryGuest(session);
    }
  }, [token]);

  const fetchChatHistoryAuth = async () => {
    try {
      const response = await axios.get("http://localhost:5000/chat/history");
      if (response.data && response.data.chat_history) {
        setMessages(response.data.chat_history);
      }
    } catch (error) {
      console.error("Error fetching chat history (auth):", error);
    }
  };

  const fetchChatHistoryGuest = async (session) => {
    try {
      const response = await axios.get(`http://localhost:5000/chat/history?session_id=${session}`);
      if (response.data && response.data.chat_history) {
        setMessages(response.data.chat_history);
      }
    } catch (error) {
      console.error("Error fetching chat history (guest):", error);
    }
  };

  const handleSend = async () => {
    if (!input.trim()) return;
    // updating the UI with the user's message.
    setMessages(prev => [...prev, { role: "user", message: input }]);
    try {
      let response;
      if (token) {
        // if authenticated then send message without session_id
        response = await axios.post("http://localhost:5000/chat/message", {
          message: input,
          role: "user"
        });
      } else {
        // if guest then include the session_id
        response = await axios.post("http://localhost:5000/chat/message", {
          session_id: sessionId,
          message: input,
          role: "user"
        });
      }
      if (response.data && response.data.response) {
        setMessages(prev => [...prev, { role: "agent", message: response.data.response }]);
      }
      setInput("");
      scrollToBottom();
    } catch (error) {
      console.error("Error sending message:", error);
    }
  };

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  const handleToggle = () => {
    setIsOpen(!isOpen);
  };

  const handleEndChat = async () => {
    try {
      if (token) {
        await axios.post("http://localhost:5000/chat/end");
        setMessages([]);
      } else {
        await axios.post("http://localhost:5000/chat/end", { session_id: sessionId });
        setMessages([]);
        // remove the old session ID and generate a new one
        // we do this because 
        // the same guest session ID is used because it’s stored persistently in localStorage.
        // it remains the same across different logins on the same browser unless you explicitly clear or regenerate it
        // to avoid reusing the same guest session ID for different users, clear the localStorage value when a user logs in or out

// Clearing/Regenerating the Guest Session ID ensures that
// Each new session starts with a fresh identifier
// Chat histories are isolated between different users or sessions
// There’s no accidental carry-over of messages from a previous session or user

// Not clearing it may lead to:
// The same guest session ID being reused across different user sessions
// Mixing of chat data between sessions, which can be confusing and possibly a security or privacy issue

        localStorage.removeItem("chat_session_id");
        const newSession = "session-" + Math.random().toString(36).substr(2, 9);
        localStorage.setItem("chat_session_id", newSession);
        setSessionId(newSession);
      }
    } catch (error) {
      console.error("Error ending chat:", error);
    }
  };

  return (
    <>
      {isOpen && (
        <div className="chat-window">
          <div className="chat-header">
            <span>Chat with Agent</span>
            <button onClick={handleToggle}>X</button>
          </div>
          <div className="chat-body">
            {messages.map((msg, idx) => (
              <div key={idx} className={`chat-message ${msg.role}`}>
                <span>{msg.message}</span>
              </div>
            ))}
            <div ref={messagesEndRef} />
          </div>
          <div className="chat-footer">
            <input 
              type="text" 
              placeholder="Type your message..." 
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleSend()}
            />
            <button onClick={handleSend}>Send</button>
            <button onClick={handleEndChat}>End Chat</button>
          </div>
        </div>
      )}
      <div className="chat-icon" onClick={handleToggle}>
        <img src="/chat-icon.png" alt="Chat Icon" />
      </div>
    </>
  );
};

export default ChatWidget;
