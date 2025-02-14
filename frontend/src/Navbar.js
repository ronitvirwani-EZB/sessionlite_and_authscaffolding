import React from 'react';

function Navbar({ setView, token, handleLogout }) {
  return (
    <nav style={{ backgroundColor: '#007bff', color: '#fff', padding: '10px' }}>
      <span style={{ fontWeight: 'bold' }}>My Chat App</span>
      <div style={{ float: 'right' }}>
        {token ? (
          <button onClick={handleLogout}>Logout</button>
        ) : (
          <>
            <button onClick={() => setView('login')}>Login</button>
            <button onClick={() => setView('register')}>Register</button>
          </>
        )}
      </div>
    </nav>
  );
}

export default Navbar;
