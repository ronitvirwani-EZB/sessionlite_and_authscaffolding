import React, { useState, useEffect } from 'react';
import Navbar from './Navbar';
import LandingPage from './LandingPage';
import Login from './Login';
import Register from './Register';
import ChatWidget from './ChatWidget';

function App() {
  const [token, setToken] = useState(localStorage.getItem('token') || '');
  const [view, setView] = useState('landing'); // 'landing', 'login', or 'register'

  useEffect(() => {
    if (token) {
      localStorage.setItem('token', token);
    } else {
      localStorage.removeItem('token');
    }
  }, [token]);

  const handleLogout = () => {
    setToken('');
    setView('landing');
    localStorage.removeItem("chat_session_id");
  };
  

  return (
    <div>
      <Navbar setView={setView} token={token} handleLogout={handleLogout} />
      {view === 'landing' && <LandingPage />}
      {view === 'login' && <Login setToken={setToken} setView={setView} />}
      {view === 'register' && <Register setToken={setToken} setView={setView} />}
      {/* ChatWidget always visible in the bottom-right */}
      <ChatWidget token={token} />
    </div>
  );
}

export default App;
