from flask import render_template, request, redirect, url_for, flash, jsonify
from werkzeug.utils import secure_filename
from functools import wraps
from app.models import User
from app.models import ThreatReport
import os

from app import db
from app.models import ThreatReport
from app.main import main_bp

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace("Bearer ", "")
        user = User.query.filter_by(token=token).first()
        if not user or user.role != 'admin':
            return jsonify({"error": "Admin privileges required"}), 403
        return f(*args, **kwargs)
    return decorated_function

@main_bp.route('/')
def home():
    return render_template('report.html')

@main_bp.route('/new_path', methods=['GET'])
def another_path():
    threats = ThreatReport.query.all()
    threat_list = [t.as_dict() for t in threats]
    return jsonify({'threats': threat_list})

@main_bp.route('/submit-threat', methods=['POST'])
def submit_threat():
    # Extract form data
    threat_title = request.form.get('threat_title')
    summary = request.form.get('summary')
    iocs = request.form.get('iocs', 'None provided')
    affected_platforms = request.form.get('affected_platforms', 'None specified')
    detailed_description = request.form.get('detailed_description')
    impact_type = request.form.get('impact_type')
    severity_level = request.form.get('severity_level')
    mitigation_actions = request.form.get('mitigation_actions', 'No actions taken yet')

    # Handle file upload
    attachment = request.files.get('attachment')
    attachment_path = None
    if attachment and attachment.filename != '':
        filename = secure_filename(attachment.filename)
        attachment_path = os.path.join(main_bp.root_path, '..', '..', 'uploads', filename)
        attachment.save(attachment_path)

    # Create a new ThreatReport record
    threat_report = ThreatReport(
        threat_title=threat_title,
        summary=summary,
        iocs=iocs,
        affected_platforms=affected_platforms,
        detailed_description=detailed_description,
        impact_type=impact_type,
        severity_level=severity_level,
        mitigation_actions=mitigation_actions,
        attachment_path=attachment_path
    )

    db.session.add(threat_report) #TODO: Capture on fail, add exceptions
    db.session.commit() # Adding to DB with help of ORM

    # Flash a success message
    flash("Threat report submitted successfully!", "success") # TODO: Implement python logger 
    # Just returns theat was submited
    return redirect(url_for('main_bp.home')) # Return to this page
