import React, { useState } from 'react';
import { createPackage } from '../api/apiService';
import './ComplianceBuilder.css';

function ComplianceBuilder() {
    const [packageName, setPackageName] = useState("");
    const [selectedScripts, setSelectedScripts] = useState([]);

    const handleCreatePackage = async () => {
        // const packageData = { name: packageName, scripts: selectedScripts };
        try {
            // await createPackage(packageData);
            alert("Compliance package created successfully!");
        } catch (error) {
            console.error("Error creating package:", error);
        }
    };

    const handleCheckboxChange = (event) => {
        const { value, checked } = event.target;
        setSelectedScripts((prevScripts) =>
            checked ? [...prevScripts, value] : prevScripts.filter((script) => script !== value)
        );
    };

    return (
        <div className="compliance-builder">
            <h2>Create Compliance Package</h2>
            <input
                type="text"
                placeholder="Package Name"
                value={packageName}
                onChange={(e) => setPackageName(e.target.value)}
            />
            <div className="checkbox-container">
                <label>
                    <input
                        type="checkbox"
                        value="Check_encryption_rules"
                        onChange={handleCheckboxChange}
                    />
                    Encryption Rules Check
                </label>
                <label>
                    <input
                        type="checkbox"
                        value="Check_firewall_rules"
                        onChange={handleCheckboxChange}
                    />
                    Firewall Rules Check
                </label>
                {/* Add more check options here as needed */}
            </div>
            <button onClick={handleCreatePackage}>Save Package</button>
        </div>
    );
}

export default ComplianceBuilder;
