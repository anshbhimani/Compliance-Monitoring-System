// components/Navbar.js
import React from 'react';
import './Navbar.css';

function Navbar() {
    return (
        <nav className="navbar">
            <h2 className='main-heading'>Compliance Monitoring Tool</h2>
            <ul className="nav-list">
                <li><a href="#description">About</a></li>
                <li><a href="#credentials">SSH Credentials</a></li>
                <li><a href="#dashboard">Dashboard</a></li>
                <li><a href="#complianceBuilder">Compliance Builder</a></li>
            </ul>
        </nav>
    );
}

export default Navbar;
