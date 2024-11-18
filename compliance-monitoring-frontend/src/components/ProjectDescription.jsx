// components/ProjectDescription.js
import React from 'react';
import './ProjectDescription.css';

function ProjectDescription() {
    return (
        <section id="description" className="description">
            <h2>About the Compliance Monitoring Tool</h2>
            <p>
                This tool helps ensure your organization’s compliance with industry standards by automating checks for 
                PCI DSS, GDPR, HIPAA, and other compliance standards. It offers a dashboard for running checks, 
                viewing results, and creating compliance packages. The interface is user-friendly and provides real-time 
                feedback on compliance statuses to keep your system secure and compliant.
            </p>
        </section>
    );
}

export default ProjectDescription;
