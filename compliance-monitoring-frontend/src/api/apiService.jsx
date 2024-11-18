import axios from 'axios';

const api = axios.create({
    baseURL: 'http://localhost:5000/api/scripts/',  // Ensure this matches your backend URL
});

export const runCheck = (scriptName) => {
    return api.post(`/${scriptName}`, { script_name: scriptName });
};

export const createPackage = (packageData) => {
    return api.post('/create_package', packageData);
};
