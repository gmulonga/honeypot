from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, JSON, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
from app.core.config import settings

engine = create_engine(
    settings.DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

class UploadedFile(Base):
    __tablename__ = "uploaded_files"
    
    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String, nullable=False)
    honeypot_type = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    uploaded_at = Column(DateTime, default=datetime.utcnow)
    file_size = Column(Integer, nullable=False)
    content_type = Column(String, nullable=False)
    
    # Relationships
    analysis = relationship("AnalysisResult", back_populates="file", uselist=False)
    attacks = relationship("AttackLog", back_populates="file")

class AnalysisResult(Base):
    __tablename__ = "analysis_results"
    
    id = Column(Integer, primary_key=True, index=True)
    file_id = Column(Integer, ForeignKey("uploaded_files.id"), nullable=False)
    total_attacks = Column(Integer, default=0)
    unique_attackers = Column(Integer, default=0)
    attack_distribution = Column(JSON, nullable=True)
    hourly_pattern = Column(JSON, nullable=True)
    average_severity = Column(Integer, default=0)
    high_severity_attacks = Column(Integer, default=0)
    mitre_techniques = Column(JSON, nullable=True)
    timeline_data = Column(JSON, nullable=True)
    analyzed_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    file = relationship("UploadedFile", back_populates="analysis")
    stix_reports = relationship("STIXReport", back_populates="analysis")

class AttackLog(Base):
    __tablename__ = "attack_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    file_id = Column(Integer, ForeignKey("uploaded_files.id"), nullable=False)
    timestamp = Column(DateTime, nullable=False)
    source_ip = Column(String, nullable=False)
    destination_ip = Column(String, nullable=True)
    port = Column(Integer, nullable=True)
    protocol = Column(String, nullable=True)
    attack_type = Column(String, nullable=False)
    payload = Column(JSON, nullable=True)
    severity = Column(Integer, default=5)
    country = Column(String, nullable=True)
    city = Column(String, nullable=True)
    
    # Relationships
    file = relationship("UploadedFile", back_populates="attacks")

class STIXReport(Base):
    __tablename__ = "stix_reports"
    
    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(Integer, ForeignKey("analysis_results.id"), nullable=False)
    stix_bundle = Column(JSON, nullable=False)
    generated_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    analysis = relationship("AnalysisResult", back_populates="stix_reports")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def create_db_and_tables():
    Base.metadata.create_all(bind=engine)