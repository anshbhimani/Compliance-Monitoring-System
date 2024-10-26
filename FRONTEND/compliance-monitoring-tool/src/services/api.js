// src/services/api.js

import axios from 'axios';

const API_BASE_URL = 'http://localhost:5000'; // Adjust according to your Flask backend URL

export const getComplianceChecks = async () => {
    const response = await axios.get(`${API_BASE_URL}/api/compliance-checks`);
    return response.data;
};

export const getInsights = async () => {
    const response = await axios.get(`${API_BASE_URL}/api/insights`);
    return response.data;
};
