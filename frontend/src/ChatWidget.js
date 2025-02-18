
import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import './ChatWidget.css';

// a function to generate a fingerprint based on available browser properties
async function generateFingerprint() {
  // we will combine user agent, language, screen width, screen height, and color depth
  const data = [
    navigator.userAgent, // this property returns a string containing details about the browser and operating system
    navigator.language, // this property returns the preferred language of the user 
    window.screen.width, // this returns the width of the visitor's screen in pixels.
    window.screen.height,  // this returns the height of the visitor's screen in pixels
    window.screen.colorDepth // this indicates the number of bits used to display one pixel
  ].join('-');
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(data);
  // we then use crypto.subtle.digest to generate a sha-256 hash
  const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  return hashHex;
}

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
      axios.defaults.headers.common["authorization"] = `bearer ${token}`;
      fetchChatHistoryAuth();
    } else {
      // for guest more we generate a fingerprint id and use it as the session id
      generateFingerprint().then(fp => {
        setSessionId(fp);
        fetchChatHistoryGuest(fp);
      });
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
        // for guest mode, we do not clear the fingerprint; since it's generated from browser data, it remains constant
        // if desired, we could choose to prompt for a new guest session, but fingerprint remains persistent
      }
    } catch (error) {
      console.error("error ending chat:", error);
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
