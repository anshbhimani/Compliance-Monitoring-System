import React, { useState } from 'react';
import Dashboard from './components/Dashboard';
import CredentialForm from './components/CredentialForm';
import Navbar from './components/Navbar';
import ProjectDescription from './components/ProjectDescription';
import ScriptManager from './components/ScriptManger';
import ComplianceBuilder from './components/Compliance_Builder';


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
            <main>
                {/* Section for managing scripts */}
                <section>
                    <ScriptManager />
                </section>
                <section>
                    <ComplianceBuilder />
                </section>
            </main>
        </div>
    );
}

export default App;
