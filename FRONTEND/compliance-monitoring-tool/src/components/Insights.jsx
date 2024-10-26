// src/components/Insights.js

import React, { useEffect, useState } from 'react';
import { getInsights } from '../services/api';
import { Card, CardContent, Typography } from '@mui/material';

const Insights = () => {
    const [insights, setInsights] = useState([]);

    useEffect(() => {
        const fetchInsights = async () => {
            const data = await getInsights();
            setInsights(data);
        };
        fetchInsights();
    }, []);

    return (
        <div>
            {insights.map((insight, index) => (
                <Card key={index} style={{ margin: '10px' }}>
                    <CardContent>
                        <Typography variant="h5">{insight.title}</Typography>
                        <Typography color="textSecondary">{insight.description}</Typography>
                    </CardContent>
                </Card>
            ))}
        </div>
    );
};

export default Insights;
