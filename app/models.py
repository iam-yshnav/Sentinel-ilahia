from app import db
from datetime import datetime
from werkzeug.security import generate_password_hash
from werkzeug.security import check_password_hash

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

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    token = db.Column(db.String(255), nullable=True)
    role = db.Column(db.String(50), default='user')  # or 'admin'

    # Additional user info
    name = db.Column(db.String(120), nullable=True)
    salutation = db.Column(db.String(50), nullable=True)
    company = db.Column(db.String(120), nullable=True)
    designation = db.Column(db.String(120), nullable=True)
    team = db.Column(db.String(120), nullable=True)
    domain = db.Column(db.String(120), nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(password, self.password_hash)

    def __repr__(self):
        return f'<User {self.username}>'