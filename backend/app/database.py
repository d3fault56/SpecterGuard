from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
from app.config import get_settings

settings = get_settings()

engine = create_engine(
    settings.database_url,
    connect_args={"check_same_thread": False},
)

SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()


class ScanRecord(Base):
    """Stores scan history for later analysis."""
    __tablename__ = "scans"
    
    id = Column(Integer, primary_key=True, index=True)
    input_type = Column(String, index=True)
    input_content = Column(Text)
    verdict = Column(String)
    confidence = Column(Float)
    explanation = Column(Text)
    red_flags = Column(Text)
    analyzer_used = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)


class PhishingPattern(Base):
    """Phase 2: Known phishing patterns and indicators."""
    __tablename__ = "phishing_patterns"
    
    id = Column(Integer, primary_key=True, index=True)
    pattern_type = Column(String, index=True)
    pattern = Column(String, unique=True, index=True)
    risk_level = Column(String)
    description = Column(Text)
    confidence_boost = Column(Float, default=0.1)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


SEED_PHISHING_PATTERNS = [
    # Urgency phrases
    {
        "pattern_type": "phrase",
        "pattern": "verify your account",
        "risk_level": "high",
        "description": "Common phishing phrase requesting account verification",
        "confidence_boost": 0.12,
    },
    {
        "pattern_type": "phrase",
        "pattern": "confirm your identity",
        "risk_level": "high",
        "description": "Credential phishing attempt",
        "confidence_boost": 0.12,
    },
    {
        "pattern_type": "phrase",
        "pattern": "act now",
        "risk_level": "high",
        "description": "Creates artificial urgency typical of scams",
        "confidence_boost": 0.1,
    },
    {
        "pattern_type": "phrase",
        "pattern": "click here immediately",
        "risk_level": "high",
        "description": "Urgency + direct action (phishing indicator)",
        "confidence_boost": 0.12,
    },
    {
        "pattern_type": "phrase",
        "pattern": "your account will be closed",
        "risk_level": "high",
        "description": "Account closure threat (common scam)",
        "confidence_boost": 0.15,
    },
    {
        "pattern_type": "phrase",
        "pattern": "unusual activity detected",
        "risk_level": "medium",
        "description": "Fake security alert",
        "confidence_boost": 0.1,
    },
    # Domain typosquatting
    {
        "pattern_type": "domain",
        "pattern": "amaz0n.com",
        "risk_level": "critical",
        "description": "Amazon typosquat (0 instead of o)",
        "confidence_boost": 0.25,
    },
    {
        "pattern_type": "domain",
        "pattern": "paypa1.com",
        "risk_level": "critical",
        "description": "PayPal typosquat (1 instead of l)",
        "confidence_boost": 0.25,
    },
    {
        "pattern_type": "domain",
        "pattern": "appl3.com",
        "risk_level": "critical",
        "description": "Apple typosquat (3 instead of e)",
        "confidence_boost": 0.25,
    },
    {
        "pattern_type": "domain",
        "pattern": "g00gle.com",
        "risk_level": "critical",
        "description": "Google typosquat (00 instead of oo)",
        "confidence_boost": 0.25,
    },
    {
        "pattern_type": "domain",
        "pattern": "m1crosoft.com",
        "risk_level": "critical",
        "description": "Microsoft typosquat (1 instead of i)",
        "confidence_boost": 0.25,
    },
    # Credential requests
    {
        "pattern_type": "phrase",
        "pattern": "enter your password",
        "risk_level": "critical",
        "description": "Direct credential request",
        "confidence_boost": 0.25,
    },
    {
        "pattern_type": "phrase",
        "pattern": "enter your cvv",
        "risk_level": "critical",
        "description": "Credit card phishing",
        "confidence_boost": 0.25,
    },
    {
        "pattern_type": "phrase",
        "pattern": "social security number",
        "risk_level": "critical",
        "description": "Identity theft attempt",
        "confidence_boost": 0.25,
    },
    # Financial requests
    {
        "pattern_type": "phrase",
        "pattern": "wire transfer",
        "risk_level": "high",
        "description": "Money transfer request",
        "confidence_boost": 0.15,
    },
    {
        "pattern_type": "phrase",
        "pattern": "update payment method",
        "risk_level": "high",
        "description": "Payment credential harvest",
        "confidence_boost": 0.12,
    },
    {
        "pattern_type": "phrase",
        "pattern": "refund pending",
        "risk_level": "high",
        "description": "False refund promise",
        "confidence_boost": 0.12,
    },
]


def seed_patterns(db):
    """Seed phishing pattern database on first run."""
    
    for pattern_data in SEED_PHISHING_PATTERNS:
        existing = db.query(PhishingPattern).filter(
            PhishingPattern.pattern == pattern_data["pattern"]
        ).first()
        
        if not existing:
            pattern = PhishingPattern(**pattern_data)
            db.add(pattern)
    
    db.commit()


Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        seed_patterns(db)
        yield db
    finally:
        db.close()