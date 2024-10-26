// src/App.js

import React from 'react';
import Header from './components/Header';
import ComplianceCheck from './components/ComplianceCheck';
import Insights from './components/Insights';
import { Container } from '@mui/material';
import './App.css';

const App = () => (
    <Container>
        <Header />
        <ComplianceCheck />
        <Insights />
    </Container>
);

export default App;
