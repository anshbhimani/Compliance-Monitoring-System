// SSH_CREDS.jsx
import React, { useState } from 'react';
import axios from 'axios';
import './CredentialForm.css'; // Add CSS for modal styling

const CredentialForm = ({ onClose }) => {
  const [hostname, setHostname] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const response = await axios.post('http://localhost:5000/store_credentials', {
        hostname,
        username,
        password,
      });
      alert('Credentials stored successfully!');
      onClose(); // Close modal on successful submission
    } catch (error) {
      console.error('Error storing credentials:', error);
      alert('Failed to store credentials.');
    }
  };

  return (
    <div className="modal-overlay">
      <div className="modal-content">
        <button className="close-btn" onClick={onClose}>&times;</button>
        <form onSubmit={handleSubmit}>
          <h2>Store SSH Credentials</h2>
          <div>
            <label>
              IP Address:
              <input
                type="text"
                value={hostname}
                onChange={(e) => setHostname(e.target.value)}
                required
              />
            </label>
          </div>
          <div>
            <label>
              Username:
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
              />
            </label>
          </div>
          <div>
            <label>
              Password:
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </label>
          </div>
          <button type="submit">Store Credentials</button>
        </form>
      </div>
    </div>
  );
};

export default CredentialForm;
