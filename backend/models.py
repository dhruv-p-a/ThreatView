from sqlalchemy import Column, Integer, String, DateTime, Boolean
from database import Base
import datetime

class Threat(Base):
    """
    SQLAlchemy model for the 'threats' table.
    Stores various Indicators of Compromise (IoCs).
    """
    __tablename__ = "threats"

    id = Column(Integer, primary_key=True, index=True)

    # The actual indicator (IP, Domain name, or full URL)
    value = Column(String, unique=True, index=True, nullable=False)

    # Classification: 'IP', 'Domain', or 'URL'
    type = Column(String)

    # Where the intel came from: 'AlienVault OTX' or 'PhishTank'
    source = Column(String)

    # Description of the threat: 'Phishing', 'Malware', 'Botnet', etc.
    threat_type = Column(String)

    # NEW: Geolocation data
    country = Column(String, default="Unknown")

    # NEW: Brand monitoring flag
    brand_match = Column(Boolean, default=False)

    # Timestamp of when we added it to our database
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
