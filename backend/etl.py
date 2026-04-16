import requests
import datetime
import logging
import os
from database import SessionLocal, engine, Base
from models import Threat

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# List of domains to monitor for brand protection
MONITORED_DOMAINS = ["google.com", "microsoft.com", "apple.com", "mycompany.com"]

# Optional: Load SendGrid API Key (User must set this in environment variables)
SENDGRID_API_KEY = os.environ.get("SENDGRID_API_KEY")

def send_email_alert(threat):
    """
    Sends an email alert using SendGrid when a critical threat is detected.
    """
    if not SENDGRID_API_KEY:
        logger.warning(f"Email Alert: SendGrid Key missing. Printing to console: [ALERT] {threat.value}")
        return

    try:
        from sendgrid import SendGridAPIClient
        from sendgrid.helpers.mail import Mail

        message = Mail(
            from_email='alerts@threatview.app',
            to_emails='security-team@mycompany.com', # Change to your alert email
            subject='🚨 ThreatView Alert: Malicious Activity Detected',
            plain_text_content=(
                f"Threat Details:\n"
                f"----------------\n"
                f"Indicator: {threat.value}\n"
                f"Type: {threat.type}\n"
                f"Category: {threat.threat_type}\n"
                f"Source: {threat.source}\n"
                f"Detected At: {threat.created_at} UTC\n"
            )
        )
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        sg.send(message)
        logger.info(f"Email alert successfully sent for {threat.value}")
    except Exception as e:
        logger.error(f"Failed to send email alert: {e}")

def get_country_from_ip(ip):
    """
    Simple IP Geolocation using a public API.
    """
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        if response.status_code == 200:
            return response.json().get("country", "Unknown")
    except:
        pass
    return "Unknown"

def fetch_otx_data():
    url = "https://otx.alienvault.com/api/v1/pulses/recent"
    try:
        response = requests.get(url, timeout=12)
        data = response.json()
        threats = []
        for pulse in data.get('results', [])[:15]:
            p_name = pulse.get('name', 'Malicious Activity')
            for indicator in pulse.get('indicators', [])[:5]:
                if indicator['type'] in ['IPv4', 'domain']:
                    threats.append({
                        "type": "IP" if indicator['type'] == 'IPv4' else "Domain",
                        "value": indicator['indicator'],
                        "source": "AlienVault OTX",
                        "threat_type": p_name,
                        "created_at": datetime.datetime.utcnow()
                    })
        return threats
    except Exception as e:
        logger.error(f"OTX Error: {e}")
    return []

def fetch_phishtank_data():
    url = "https://data.phishtank.com/data/online-valid.json"
    headers = {'User-Agent': 'phishtank/ThreatView'}
    try:
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 200:
            data = response.json()
            return [{
                "type": "URL",
                "value": item['url'],
                "source": "PhishTank",
                "threat_type": "Phishing",
                "created_at": datetime.datetime.utcnow()
            } for item in data[:40]]
    except Exception as e:
        logger.error(f"PhishTank Error: {e}")
    return []

def run_etl():
    logger.info("ETL Started...")
    db = SessionLocal()

    # 1. Fetch live data
    incoming_data = fetch_otx_data() + fetch_phishtank_data()

    # 2. Add Dummy/Test Data (Always ensures there's something to show)
    test_threats = [
        {"type": "IP", "value": "103.245.10.2", "source": "Internal-Scan", "threat_type": "Malware", "country": "India", "brand_match": False},
        {"type": "Domain", "value": "google-security-update.com", "source": "Brand-Monitor", "threat_type": "Phishing", "country": "USA", "brand_match": True},
        {"type": "URL", "value": "http://payment-mycompany-check.com/login", "source": "PhishTank", "threat_type": "Phishing", "country": "Germany", "brand_match": True},
        {"type": "IP", "value": "185.220.101.5", "source": "AlienVault OTX", "threat_type": "Botnet", "country": "Russia", "brand_match": False}
    ]

    # Merge test data with live data
    all_data = incoming_data + test_threats

    for entry in all_data:
        # Check if already exists to avoid duplication
        exists = db.query(Threat).filter(Threat.value == entry['value']).first()
        if not exists:
            # Add country if missing
            if entry.get('type') == "IP" and entry.get('country') == "Unknown":
                entry['country'] = get_country_from_ip(entry['value'])

            # Re-check brand matching
            entry['brand_match'] = any(domain in entry['value'] for domain in MONITORED_DOMAINS)

            new_threat = Threat(**entry, created_at=datetime.datetime.utcnow())
            db.add(new_threat)

            # --- Trigger logic for Email Alert ---
            # Trigger if threat is Phishing, contains Malware, or is a Brand match
            if (entry.get('threat_type') == "Phishing" or
                "Malware" in entry.get('threat_type') or
                entry.get('brand_match')):
                send_email_alert(new_threat)

    db.commit()
    db.close()
    logger.info("ETL Finished. Data synchronized.")

if __name__ == "__main__":
    run_etl()
