from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Boolean, JSON, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime

Base = declarative_base()

class EntityRecord(Base):
    """Stores the aggregated sliding window features for individual IPs/Domains."""
    __tablename__ = 'entity_windows'
    
    id = Column(Integer, primary_key=True, index=True)
    entity_id = Column(String, index=True) # IP or Domain
    entity_type = Column(String) # 'host', 'domain'
    window_start = Column(DateTime, index=True)
    window_end = Column(DateTime)
    
    # Statistical properties
    bytes_in = Column(Float, default=0)
    bytes_out = Column(Float, default=0)
    conn_count = Column(Integer, default=0)
    domain_entropy = Column(Float, default=0)
    
    # Enrichments
    ip_reputation_score = Column(Float, default=0)
    
    # Embeddings/References
    node2vec_embedding_ref = Column(String, nullable=True) # Could be a link to Redis

    # Latest scoring from the ML pipeline
    anomaly_score = Column(Float, nullable=True)
    risk_level = Column(String, nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)

class Alert(Base):
    """Real-time fired alerts displayed in the Dashboard."""
    __tablename__ = 'alerts'
    
    id = Column(Integer, primary_key=True, index=True)
    entity_id = Column(String, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    score = Column(Float)
    risk_level = Column(String) # 'critical', 'warning', 'info'
    
    # Explanation
    contributors = Column(JSON) # e.g. [{"feature": "bytes_out", "score": 2.1}]
    
    # For red-team analysis (was this alert generated during a sim?)
    is_synthetic = Column(Boolean, default=False)
    experiment_id = Column(String, nullable=True)

class ExperimentReport(Base):
    """Storage for Red vs Blue auto-evaluations."""
    __tablename__ = 'experiments'
    
    id = Column(String, primary_key=True, index=True)
    attack_type = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    # Metric JSON block
    metrics = Column(JSON)
