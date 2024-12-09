# Compliance Monitoring System

## Project Overview
This project is a Compliance Monitoring System designed to streamline compliance tracking and reporting. It comprises a backend built with Python and a modern frontend using Vite with React.

## Features
- Backend: Python-based server for handling compliance logic and reporting
- Frontend: Interactive UI built with React and TailwindCSS
- Deployed: Live Demo available (https://compliance-monitoring-system.vercel.app/)

## Project Structure
```
Compliance-Monitoring-System
├── Backend
│   ├── app.py              # Backend entry point
│   ├── models.py           # Data models
│   ├── reporting.py        # Reporting logic
│   ├── tasks.py            # Task scheduler
│   ├── requirements.txt    # Python dependencies
│   └── ...                 # Other utility scripts and configs
├── compliance-monitoring-frontend
│   ├── index.html          # Entry HTML file
│   ├── package.json        # Frontend dependencies
│   ├── src/                # React components
│   └── ...                 # Other frontend configs and assets
```

## How It Works

![(Flowchart.jpg)](https://github.com/anshbhimani/Compliance-Monitoring-System/blob/anshbhimani-patch-1/Flowchart.jpg)


### Backend (Python-based)
The backend, built using Flask, provides APIs for compliance tracking and system management:

#### Core Logic (app.py):
- Hosts API endpoints to interact with the frontend
- Handles user requests for managing compliance groups and executing scripts
- Includes utilities like logging and SSH connections using paramiko for server interactions

#### Compliance Scripts (scripts/):
- Stores pre-built scripts for automated compliance checks
- Scripts can be dynamically loaded and executed based on the requested action

#### Data Management:
- Uses in-memory or file-based mechanisms to store compliance groups and results
- Future enhancements could integrate a relational database (e.g., PostgreSQL) for persistence

#### Key Features:
- Logging: Captures activities in LogFile.log for monitoring and debugging
- Task Scheduling: Automates compliance checks using a scheduler
- Security: Integrates role-based access control (Admin and User) to protect critical operations

### Frontend (React + Vite)
The frontend provides an intuitive UI for interacting with the system, deployed on Vercel:

#### Application Structure:
- Main Files:
  - App.jsx: Main entry point for the application logic
  - main.jsx: Bootstraps the React app
- Styling: App.css and index.css handle the visual design, leveraging TailwindCSS

#### Core Components:
- Dashboard: Displays an overview of compliance statuses and pending actions
- Compliance Groups: Manage configurations, view logs, and schedule checks
- Reports: View results from executed checks and download reports as PDFs

#### API Integration:
- A dedicated api/ module interfaces with the backend to fetch data and send updates
- Provides seamless synchronization between user actions on the UI and the backend's operations

#### Static Assets:
- Images and Icons: Stored in the assets/ folder for branding and UI elements

## Workflow

### User Authentication:
- Admins and users log in with specific credentials
- Role-based authentication ensures secure access to sensitive actions

### Configuration:
- Users define compliance groups and associate them with scripts or actions to be performed

### Execution:
- Backend triggers scripts (via APIs) on designated servers, networks, or cloud platforms
- Results are processed and stored for further analysis

### Reporting:
- Results are visualized on the dashboard
- Reports are generated and made available for download

### Automation:
- Schedulers automate recurring compliance checks
- Notifies users of anomalies or success statuses

## Setup Instructions

### Backend
Navigate to the Backend directory:
```bash
cd Backend
```

Install dependencies:
```bash
pip install -r requirements.txt
```

Run the backend server:
```bash
python app.py
```

### Frontend
Navigate to the compliance-monitoring-frontend directory:
```bash
cd compliance-monitoring-frontend
```

Install dependencies:
```bash
npm install
```

Start the development server:
```bash
npm run dev
```

## UI Previews
Screenshots of the deployed UI are included:
- Dashboard
- Compliance Reports

## License
This project is licensed under the MIT License. See the LICENSE file for details.

## Contributions
Feel free to fork the repository and submit pull requests for any enhancements or bug fixes.
