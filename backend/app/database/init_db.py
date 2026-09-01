import passlib.hash
from sqlalchemy.orm import Session
from backend.app.database.session import engine, Base, SessionLocal
from backend.app.models import (
    User, Campaign, Incident, ScamDNA, Entity, EntityMention,
    Relationship, Evidence, RiskAssessment, Observation, ThreatActor,
    MalwareFamily, AttackTechnique, Investigation, AIReport, AuditLog
)
from backend.app.core.logging import logger

DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_EMAIL = "admin@campaignx.ai"
DEFAULT_ADMIN_PASSWORD = "admin"


def get_password_hash(password: str) -> str:
    from passlib.context import CryptContext
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    return pwd_context.hash(password)


def init_db(db: Session = None):
    """Create all database tables and seed baseline admin user & MITRE techniques."""
    logger.info("Creating database tables...")
    Base.metadata.create_all(bind=engine)
    
    close_at_end = False
    if db is None:
        db = SessionLocal()
        close_at_end = True

    try:
        # Check admin user
        admin = db.query(User).filter(User.username == DEFAULT_ADMIN_USERNAME).first()
        if not admin:
            admin = User(
                username=DEFAULT_ADMIN_USERNAME,
                email=DEFAULT_ADMIN_EMAIL,
                hashed_password=get_password_hash(DEFAULT_ADMIN_PASSWORD),
                role="admin",
                is_active=True
            )
            db.add(admin)
            logger.info("Admin user created.")

        # Seed core MITRE ATT&CK techniques
        baseline_techniques = [
            ("T1566.002", "Phishing: Spearphishing Link", "Initial Access", "Adversaries send spearphishing emails with malicious links."),
            ("T1566.001", "Phishing: Spearphishing Attachment", "Initial Access", "Adversaries send spearphishing emails with malicious attachments."),
            ("T1598.003", "Phishing for Information: Spearphishing Link", "Reconnaissance", "Adversaries send phishing messages to gather sensitive information."),
            ("T1059.001", "Command and Scripting Interpreter: PowerShell", "Execution", "Adversaries abuse PowerShell commands and scripts."),
            ("T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control", "Adversaries communicate using application layer protocols (HTTP/HTTPS)."),
            ("T1110.001", "Brute Force: Password Guessing", "Credential Access", "Adversaries attempt to guess valid passwords."),
            ("T1204.001", "User Execution: Malicious Link", "Execution", "An adversary relies on a user clicking a link."),
            ("T1499.001", "Endpoint Denial of Service: OS Exhaustion", "Impact", "Adversaries disrupt system availability."),
        ]

        for tid, name, tactic, desc in baseline_techniques:
            existing = db.query(AttackTechnique).filter(AttackTechnique.technique_id == tid).first()
            if not existing:
                tech = AttackTechnique(
                    technique_id=tid,
                    name=name,
                    tactic=tactic,
                    description=desc
                )
                db.add(tech)

        db.commit()
        logger.info("Database initialized and baseline data seeded.")
    except Exception as e:
        db.rollback()
        logger.error(f"Error initializing database: {e}")
        raise e
    finally:
        if close_at_end:
            db.close()


if __name__ == "__main__":
    init_db()
