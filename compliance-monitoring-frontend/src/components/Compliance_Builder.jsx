import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './Compliance_Builder.css';

const ComplianceBuilder = () => {
    const [scripts, setScripts] = useState([]);
    const [groupName, setGroupName] = useState('');
    const [selectedScripts, setSelectedScripts] = useState([]);
    const [complianceGroups, setComplianceGroups] = useState([]);

    useEffect(() => {
        axios.get('http://localhost:5000/api/scripts')
            .then(response => setScripts(response.data))
            .catch(error => console.error(error));

        axios.get('http://localhost:5000/api/compliance-groups')
            .then(response => setComplianceGroups(response.data))
            .catch(error => console.error(error));
    }, []);

    const handleScriptSelection = (script) => {
        setSelectedScripts(prev => prev.includes(script) ? prev.filter(s => s !== script) : [...prev, script]);
    };

    const handleCreateGroup = () => {
        const groupData = { name: groupName, scripts: selectedScripts };
        axios.post('http://localhost:5000/api/compliance-groups', groupData)
            .then(response => {
                setComplianceGroups([...complianceGroups, response.data]);
                setGroupName('');
                setSelectedScripts([]);
            })
            .catch(error => console.error(error));
    };

    return (
        <div className="compliance-builder">
            <h2>Create Compliance Group</h2>
            <input
                type="text"
                placeholder="Group Name"
                value={groupName}
                onChange={(e) => setGroupName(e.target.value)}
                className="input-field"
            />
            <div className="scripts-container">
                <h3>Select Scripts</h3>
                {scripts.map(script => (
                    <div key={script} className="script-item">
                        <input
                            type="checkbox"
                            checked={selectedScripts.includes(script)}
                            onChange={() => handleScriptSelection(script)}
                        />
                        {script}
                    </div>
                ))}
            </div>
            <button onClick={handleCreateGroup} className="create-group-button">Create Group</button>

            <h2>Existing Compliance Groups</h2>
            <ul className="compliance-group-list">
                {complianceGroups.map(group => (
                    <li key={group.name}>
                        <strong>{group.name}</strong>: {group.scripts.join(', ')}
                    </li>
                ))}
            </ul>
        </div>
    );
};

export default ComplianceBuilder;
