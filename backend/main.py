from fastapi import FastAPI, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from contextlib import asynccontextmanager
from sqlalchemy import func
import uvicorn
from apscheduler.schedulers.background import BackgroundScheduler
import os

# Local imports
from database import engine, get_db, Base
from models import Threat
from etl import run_etl

# Create database tables
Base.metadata.create_all(bind=engine)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Run ETL once on startup to populate data
    print("--- Startup: Initializing ETL ---")
    try:
        run_etl()
        print("--- Startup: ETL Process Completed Successfully ---")
    except Exception as e:
        print(f"--- Startup: ETL Failed: {e} ---")

    # Start the scheduler to run every hour
    scheduler = BackgroundScheduler()
    scheduler.add_job(run_etl, 'interval', hours=1)
    scheduler.start()

    yield

    # Shutdown logic
    scheduler.shutdown()
    print("--- Shutdown: Cleaning up ---")

app = FastAPI(
    title="ThreatView API",
    description="A centralized dashboard for real-time threat intelligence.",
    version="1.1.0",
    lifespan=lifespan
)

# Enable CORS for frontend interaction
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def read_root():
    """Diagnostic endpoint to check if API is alive"""
    return {
        "status": "Online",
        "message": "ThreatView API is working. Check /threats for data.",
        "database_file": "threats.db"
    }

@app.get("/threats")
def get_threats(db: Session = Depends(get_db), limit: int = 50):
    """Returns the latest threats from the database"""
    threats = db.query(Threat).order_by(Threat.created_at.desc()).limit(limit).all()
    return threats

@app.get("/search")
def search_threat(value: str = Query(...), db: Session = Depends(get_db)):
    """Checks if a specific indicator exists in our database"""
    result = db.query(Threat).filter(Threat.value == value).first()
    if result:
        return {
            "status": "Malicious",
            "type": result.type,
            "source": result.source,
            "threat_type": result.threat_type,
            "detected_at": result.created_at
        }
    return {"status": "Safe", "message": "No threats found for this indicator."}

@app.get("/stats")
def get_stats(db: Session = Depends(get_db)):
    """Returns aggregated statistics for the chart"""
    phish = db.query(Threat).filter(Threat.threat_type == "Phishing").count()
    malware = db.query(Threat).filter(Threat.threat_type.contains("Malware")).count()
    total = db.query(Threat).count()
    return {
        "phishing": phish,
        "malware": malware,
        "other": max(0, total - (phish + malware))
    }

@app.get("/brand-alerts")
def get_brand_alerts(db: Session = Depends(get_db)):
    """Returns threats flagged by brand monitoring"""
    return db.query(Threat).filter(Threat.brand_match == True).all()

@app.get("/countries")
def get_country_stats(db: Session = Depends(get_db)):
    """Returns threat counts per country for the map/list"""
    results = db.query(Threat.country, func.count(Threat.id)).filter(Threat.country != "Unknown").group_by(Threat.country).all()
    return {country: count for country, count in results}

if __name__ == "__main__":
    # Ensure we use PORT env var for Render
    port = int(os.environ.get("PORT", 8080))
    print(f"Launching ThreatView Backend on http://127.0.0.1:{port}")
    uvicorn.run(app, host="0.0.0.0", port=port)
