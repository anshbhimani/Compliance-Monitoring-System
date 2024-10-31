import React, { useState } from 'react';
import Dashboard from './components/Dashboard';
import ComplianceBuilder from './components/ComplianceBuilder';
import CredentialForm from './components/CredentialForm';
import Navbar from './components/Navbar';
import ProjectDescription from './components/ProjectDescription';

function App() {
    const [isModalOpen, setIsModalOpen] = useState(false);

    const openModal = () => setIsModalOpen(true);
    const closeModal = () => setIsModalOpen(false);

    return (
        <div className="app">
            <Navbar />
            <ProjectDescription />
            <h1>Compliance Monitoring Tool</h1>
            <button onClick={openModal}>Add SSH Credentials</button>
            {isModalOpen && <CredentialForm onClose={closeModal} />}
            <Dashboard />
            <ComplianceBuilder />
        </div>
    );
}

export default App;
