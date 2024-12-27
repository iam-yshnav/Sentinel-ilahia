from app import db
from datetime import datetime

class ThreatReport(db.Model):
    __tablename__ = 'threat_reports'

    id = db.Column(db.Integer, primary_key=True)
    threat_title = db.Column(db.String(300), nullable=False) 
    summary = db.Column(db.Text) # TODO : make it nullable in future, Also put in FE validation
    iocs = db.Column(db.Text)
    affected_platforms = db.Column(db.Text)
    detailed_description = db.Column(db.Text, nullable=False)
    impact_type = db.Column(db.String(50))
    severity_level = db.Column(db.String(50)) # TODO: Restrict from frontend will be fine
    mitigation_actions = db.Column(db.Text)
    attachment_path = db.Column(db.String(250))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<ThreatReport {self.threat_title}>'

# TODO : Add user table and auth table