// components/Dashboard.js
import React, { useState, useEffect } from 'react';
import { runCheck } from '../api/apiService';
import './Dashboard.css';

function Dashboard() {
    const [checkResults, setCheckResults] = useState([]);
    const [scripts, setScripts] = useState([]);

    useEffect(() => {
        const fetchScripts = async () => {
            try {
                const response = await fetch('http://localhost:5000/api/scripts'); 
                const data = await response.json();
                setScripts(data);
            } catch (error) {
                console.error("Error fetching scripts:", error);
            }
        };

        fetchScripts();
    }, []);

    const handleRunCheck = async (scriptName) => {
        try {
            const response = await runCheck(scriptName);
            setCheckResults((prevResults) => {
                const existingResultIndex = prevResults.findIndex(check => check.scriptName === scriptName);
                if (existingResultIndex !== -1) {
                    const updatedResults = [...prevResults];
                    updatedResults[existingResultIndex] = { scriptName, result: response.data };
                    return updatedResults;
                } else {
                    return [...prevResults, { scriptName, result: response.data }];
                }
            });
        } catch (error) {
            console.error("Error running check:", error);
        }
    };

    return (
        <div id="dashboard" className="dashboard">
            <h2>Compliance Dashboard</h2>
            <h3>Available Checks</h3>
            <div className="button-container">
                {scripts.map((script, index) => (
                    <button key={index} onClick={() => handleRunCheck(script)} className="run-button">
                        Run {script}
                    </button>
                ))}
            </div>
            <h3>Results</h3>
            <table className="result-table">
                <thead>
                    <tr>
                        <th>Script Name</th>
                        <th>Result</th>
                    </tr>
                </thead>
                <tbody>
                    {checkResults.map((check, index) => (
                        <tr key={index}>
                            <td>{check.scriptName}</td>
                            <td>{renderResult(check.result)}</td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
}

function renderResult(result) {
    return Array.isArray(result) ? (
        <ul>
            {result.map((item, index) => (
                <li key={index}>{typeof item === 'string' ? item : JSON.stringify(item)}</li>
            ))}
        </ul>
    ) : (
        <span>{result}</span>
    );
}

export default Dashboard;
