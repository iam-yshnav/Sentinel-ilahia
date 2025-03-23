from app import db
from datetime import datetime
from werkzeug.security import generate_password_hash
from werkzeug.security import check_password_hash


class Organization(db.Model):
    __tablename__ = 'organizations'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), unique=True, nullable=False)
    industry = db.Column(db.String(100), nullable=True)
    is_banned = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    users = db.relationship('User', backref='organization', lazy=True)
    assets = db.relationship('Asset', backref='organization', lazy=True)

class Asset(db.Model):
    __tablename__ = 'assets'

    id = db.Column(db.Integer, primary_key=True)
    server_name = db.Column(db.String(200), nullable=False)
    os_name = db.Column(db.String(100), nullable=False)
    os_version = db.Column(db.String(50), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False, index=True)  # IPv4 & IPv6
    service_name = db.Column(db.String(100))
    service_version = db.Column(db.String(50))
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False) 
    server_purpose = db.Column(db.String(50), nullable=False)
    cpu_configuration = db.Column(db.Integer, nullable=False)  # Number of cores
    ram_capacity = db.Column(db.Integer, nullable=False)  # RAM in GB
    storage_configuration = db.Column(db.Text)
    network_configuration = db.Column(db.Text)
    security_protocols = db.Column(db.Text)
    admin_contact = db.Column(db.String(100), nullable=False)

    def __repr__(self):
        return f'<Asset {self.server_name}>'



class ThreatReport(db.Model):
    __tablename__ = 'threat_reports'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(200), default="unknown")
    threat_title = db.Column(db.String(300), nullable=False)
    summary = db.Column(db.Text)
    iocs = db.Column(db.Text)
    affected_platforms = db.Column(db.Text)
    affected_platform_ver = db.Column(db.Text)
    affected_service = db.Column(db.Text)
    affected_service_ver = db.Column(db.Text)
    detailed_description = db.Column(db.Text, nullable=False)
    impact_type = db.Column(db.String(50))
    severity_level = db.Column(db.String(50))
    mitigation_actions = db.Column(db.Text)
    attachment_path = db.Column(db.String(250))
    approved = db.Column(db.Boolean, default=False)
    deleted = db.Column(db.Boolean, default=False)  # Soft delete flag
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<ThreatReport {self.threat_title}>'
class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    token = db.Column(db.String(255), nullable=True)
    role = db.Column(db.String(50), default='normal')  # Roles: 'normal', 'company', 'admin'
    status = db.Column(db.String(20), default='pending')  # Status: 'pending', 'approved', 'revoked', 'banned'

    # Personal Details (Common for both normal and company users)
    name = db.Column(db.String(120), nullable=True)
    salutation = db.Column(db.String(50), nullable=True)

    # Company-Specific Details (Only for company users)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=True)
    company = db.Column(db.String(120), nullable=True)  # Only if organization_id is not provided
    designation = db.Column(db.String(120), nullable=True)
    team = db.Column(db.String(120), nullable=True)
    domain = db.Column(db.String(120), nullable=True)

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'
    
    def get_default_organization(self):
        if self.role == 'normal':
            return Organization.query.filter_by(name='Individual Users').first()
        return self.organization

class ThreatIntelligence(db.Model):
    __tablename__ = 'threat_intelligence'

    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False)
    asset_id = db.Column(db.Integer, db.ForeignKey('assets.id'), nullable=False)
    server_name = db.Column(db.String(200), nullable=False)
    threat_id = db.Column(db.Integer, db.ForeignKey('threat_reports.id'), nullable=False)
    state = db.Column(db.String(50), default="Triaged",nullable=False)  # e.g., 'triaged', 'mitigated'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Optional relationships for easier access from related models
    organization = db.relationship('Organization', backref=db.backref('threat_intelligence', lazy=True))
    asset = db.relationship('Asset', backref=db.backref('threat_intelligence', lazy=True))
    threat = db.relationship('ThreatReport', backref=db.backref('threat_intelligence', lazy=True))

    def __repr__(self):
        return f'<ThreatIntelligence {self.server_name} - State: {self.state}>'
