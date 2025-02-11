from flask import Blueprint, render_template, request, redirect, url_for, flash
from app.models import ThreatReport, User
from app import db

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/')
def admin_dashboard():
   
    active_threats = ThreatReport.query.filter_by(deleted=False).all()
    deleted_threats = ThreatReport.query.filter_by(deleted=True).all()  # Fetch deleted threats
    users = User.query.all()  # Fetch all users
    return render_template('admin.html', threats=active_threats, deleted_threats=deleted_threats, users=users)

@admin_bp.route('/approve_threat/<int:threat_id>', methods=['POST'])
def approve_threat(threat_id):
    threat = ThreatReport.query.get_or_404(threat_id)
    threat.approved = True
    db.session.commit()
    flash('Threat approved successfully!', 'success')
    return redirect(url_for('admin.admin_dashboard'))

@admin_bp.route('/reject_threat/<int:threat_id>', methods=['POST'])
def reject_threat(threat_id):
    threat = ThreatReport.query.get_or_404(threat_id)
    threat.approved = False
    db.session.commit()
    flash('Threat rejected successfully!', 'success')
    return redirect(url_for('admin.admin_dashboard'))

@admin_bp.route('/delete_threat/<int:threat_id>', methods=['POST'])
def delete_threat(threat_id):
    threat = ThreatReport.query.get_or_404(threat_id)
    threat.deleted = True  # Soft delete
    db.session.commit()
    flash('Threat deleted successfully!', 'success')
    return redirect(url_for('admin.admin_dashboard'))

@admin_bp.route('/retain_threat/<int:threat_id>', methods=['POST'])
def retain_threat(threat_id):
    threat = ThreatReport.query.get_or_404(threat_id)
    threat.deleted = False  # Retain (restore) threat
    db.session.commit()
    flash('Threat retained successfully!', 'success')
    return redirect(url_for('admin.admin_dashboard'))