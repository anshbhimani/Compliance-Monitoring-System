import React, { useState, useEffect } from 'react';
import axios from 'axios';

const baseUrl = 'http://localhost:5000';

const ScriptManager = () => {
    const [scripts, setScripts] = useState([]);
    const [scriptName, setScriptName] = useState('');
    const [file, setFile] = useState(null);

    useEffect(() => {
        axios.get(`${baseUrl}/api/scripts`)
            .then(response => setScripts(response.data))
            .catch(error => console.error(error));
    }, []);

    const handleFileChange = (e) => setFile(e.target.files[0]);

    const handleAddScript = async () => {
        if (!file || !scriptName) {
            alert("Please provide both a name and a file.");
            return;
        }
        
        const formData = new FormData();
        formData.append('scriptName', scriptName);
        formData.append('file', file);

        try {
            await axios.post(`${baseUrl}/api/scripts`, formData, {
                headers: { 'Content-Type': 'multipart/form-data' }
            });
            alert('Script uploaded successfully');
            setScripts([...scripts, scriptName]);
        } catch (error) {
            console.error(error);
            alert("Error uploading script");
        }
    };

    return (
        <div>
            <h2>Script Manager</h2>
            <input type="text" placeholder="Script Name" value={scriptName} onChange={(e) => setScriptName(e.target.value)} />
            <input type="file" onChange={handleFileChange} />
            <button onClick={handleAddScript}>Upload Script</button>
            <ul>
                {scripts.map(script => (
                    <li key={script}>{script}</li>
                ))}
            </ul>
        </div>
    );
};

export default ScriptManager;
