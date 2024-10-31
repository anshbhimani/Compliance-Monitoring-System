// src/components/ComplianceCheck.js

import React, { useEffect, useState } from 'react';
import { getComplianceChecks } from '../services/api';
import { Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Paper } from '@mui/material';

const ComplianceCheck = () => {
    const [checks, setChecks] = useState([]);

    useEffect(() => {
        const fetchChecks = async () => {
            const data = await getComplianceChecks();
            setChecks(data);
        };
        fetchChecks();
    }, []);

    return (
        <TableContainer component={Paper}>
            <Table>
                <TableHead>
                    <TableRow>
                        <TableCell>Check</TableCell>
                        <TableCell>Description</TableCell>
                        <TableCell>Result</TableCell>
                        <TableCell>Remedy (if failed)</TableCell>
                    </TableRow>
                </TableHead>
                <TableBody>
                    {checks.map((check, index) => (
                        <TableRow key={index}>
                            <TableCell>{check.name}</TableCell>
                            <TableCell>{check.description}</TableCell>
                            <TableCell>{check.result}</TableCell>
                            <TableCell>{check.remedy || 'N/A'}</TableCell>
                        </TableRow>
                    ))}
                </TableBody>
            </Table>
        </TableContainer>
    );
};

export default ComplianceCheck;
