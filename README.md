# ThreatView - Enterprise Threat Intelligence Dashboard

ThreatView is a centralized platform designed to analyze malicious activity by aggregating data from multiple global threat intelligence feeds. This project serves as a comprehensive tool for security analysts to monitor, search, and visualize Indicators of Compromise (IoCs) in real-time.

## 🚀 Key Features
- **Automated ETL Pipeline:** Robust data ingestion engine that synchronizes data every hour from multiple sources.
- **Searchable IoC Database:** High-performance lookup system for IP addresses, Domains, and URLs.
- **Global Threat Map:** Professional interactive visualization highlighting threat origins by country with a heatmap effect.
- **Real-time Distribution Chart:** Visual breakdown of threat categories (Phishing vs Malware vs Others) using Chart.js.
- **Brand Protection:** Real-time monitoring and alerting for impersonation of corporate domains.
- **Automated Email Notifications:** Instant alerts for critical security events via SendGrid API integration.
- **Role-Based Access Control (RBAC):** Tiered data access model:
  - **Free Tier:** Access to data from the last 24 hours.
  - **Pro Tier:** Unlimited access to historical threat intelligence.

## 📡 Intelligence Sources
- **AlienVault OTX:** Leverages community-powered IP and Domain reputation pulses.
- **PhishTank:** Integrates verified, real-time phishing URL intelligence.

## 🛠 Tech Stack
- **Backend:** Python (FastAPI), SQLAlchemy (ORM), SQLite (Database), APScheduler (Task Scheduling).
- **Frontend:** Vanilla HTML5, CSS3 (Modern Flex/Grid), JavaScript (ES6+), Chart.js, jsVectorMap.
- **Infrastructure:**
  - **Backend Hosting:** Render
  - **Frontend Hosting:** Vercel
  - **Version Control:** Git & GitHub

## 📁 Project Structure
```text
threatview/
├── backend/
│   ├── main.py          # FastAPI application, API endpoints & RBAC logic
│   ├── database.py      # SQLAlchemy configuration & SQLite connection
│   ├── models.py        # Database schema & Threat models
│   ├── etl.py           # Ingestion logic, Geolocation & Email alerts
│   └── requirements.txt # Project dependencies
├── frontend/
│   ├── index.html       # Enterprise Intelligence Dashboard UI
│   ├── style.css        # Professional styling & animations
│   └── script.js        # Dynamic data rendering & API integration
└── README.md            # Project documentation
```

## 🔑 Setup & Installation
1. **Clone the repository:**
   ```bash
   git clone https://github.com/dhruv-p-a/ThreatView.git
   cd threatview/backend
   ```
2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
3. **Environment Configuration:**
   - Set `SENDGRID_API_KEY` for email alerts.
   - Configure `MONITORED_DOMAINS` in `etl.py` for Brand Protection.
4. **Run the application:**
   ```bash
   python main.py
   ```

## 🛡 Security Intern Project
Developed as part of a Cybersecurity Software Engineering internship, focusing on ETL processes, data normalization, and actionable intelligence visualization.
