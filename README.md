# ThreatView - Threat Intelligence Dashboard

ThreatView is a full-stack web application designed to help users identify malicious IP addresses, domains, and URLs by aggregating data from open-source threat intelligence feeds.

## Features
- **Real-time Search:** Instantly check if an indicator (IP/Domain) is known to be malicious.
- **Threat Dashboard:** View a live feed of the latest threats ingested from AlienVault OTX and PhishTank.
- **Automated ETL:** A background scheduler fetches and normalizes data every hour.
- **Simple UI:** A clean, responsive dashboard built with vanilla HTML, CSS, and JS.

## Tech Stack
- **Backend:** Python 3.10+, FastAPI, SQLAlchemy, APScheduler.
- **Database:** SQLite.
- **Frontend:** HTML5, CSS3, JavaScript (ES6+).

## Project Structure
```text
threatview/
├── backend/
│   ├── main.py          # FastAPI application & Scheduler
│   ├── database.py      # SQLAlchemy configuration
│   ├── models.py        # Database schema
│   ├── etl.py           # Data Ingestion scripts
│   └── requirements.txt # Python dependencies
└── frontend/
    ├── index.html       # Main UI page
    ├── style.css        # Styling
    └── script.js        # Frontend logic
```

## Setup Instructions

### 1. Backend Setup
1. Navigate to the backend directory:
   ```bash
   cd threatview/backend
   ```
2. Create a virtual environment (optional but recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Run the backend server:
   ```bash
   python main.py
   ```
   *The server will start on `http://127.0.0.1:8000`. On first run, it will automatically pull initial data (ETL).*

### 2. Frontend Setup
1. Since the frontend is static HTML/JS, you can simply open `frontend/index.html` in any modern web browser.
2. Alternatively, use a "Live Server" extension if you're using VS Code.
3. Ensure the backend is running so the frontend can fetch data.

## Example API Responses

### GET `/threats`
```json
[
  {
    "id": 1,
    "type": "URL",
    "value": "http://malicious-site.com/login",
    "source": "PhishTank",
    "threat_type": "Phishing",
    "created_at": "2023-10-27T10:00:00"
  }
]
```

### GET `/search?value=1.2.3.4`
```json
{
  "status": "Malicious",
  "type": "IP",
  "source": "AlienVault OTX",
  "threat_type": "Botnet Activity",
  "detected_at": "2023-10-27T09:45:00"
}
```

## Notes
- **OTX API Key:** For better data, register at [AlienVault OTX](https://otx.alienvault.com/) and add your API key in `etl.py`.
- **Database:** The SQLite file `threats.db` will be created automatically in the `backend` folder.
