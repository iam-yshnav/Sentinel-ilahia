from app import db
from datetime import datetime
from werkzeug.security import generate_password_hash
from werkzeug.security import check_password_hash


class Organization(db.Model):
    __tablename__ = 'organizations'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), unique=True, nullable=False)
    industry = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    users = db.relationship('User', backref='organization', lazy=True)
    assets = db.relationship('Asset', backref='organization', lazy=True)

class Asset(db.Model):
    __tablename__ = 'assets'

    id = db.Column(db.Integer, primary_key=True)
    asset_name = db.Column(db.String(200), nullable=False)
    os_name = db.Column(db.String(100), nullable=False)
    os_version = db.Column(db.String(50), nullable=False)
    service_name = db.Column(db.String(150), nullable=True)
    service_version = db.Column(db.String(50), nullable=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class ThreatReport(db.Model):
    __tablename__ = 'threat_reports'

    id = db.Column(db.Integer, primary_key=True)
    threat_title = db.Column(db.String(300), nullable=False) 
    summary = db.Column(db.Text) # TODO : make it nullable in future, Also put in FE validation
    iocs = db.Column(db.Text)
    affected_platforms = db.Column(db.Text) # OS Limit to 3 from frontend
    affected_platform_ver = db.Column(db.Text) # Make it string with <,> and versions
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
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=True)
    # This needs to be amended by the admin, will put the checks later
    
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



