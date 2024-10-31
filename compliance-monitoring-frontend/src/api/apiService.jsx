import axios from 'axios';

const api = axios.create({
    baseURL: 'http://localhost:5000',  // Ensure this matches your backend URL
});

export const runCheck = (scriptName) => {
    return api.post('/run_check', { script_name: scriptName });
};

export const createPackage = (packageData) => {
    return api.post('/create_package', packageData);
};
