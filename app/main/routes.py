from flask import render_template, request, redirect, url_for, flash, jsonify, current_app
from werkzeug.utils import secure_filename
from functools import wraps
from app.models import User, ThreatReport
import os
from flask_jwt_extended import get_jwt_identity, jwt_required
from app import db
from app.main import main_bp

# ✅ Admin Authentication Decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace("Bearer ", "")
        user = User.query.filter_by(token=token).first()
        if not user or user.role != 'admin':
            return jsonify({"error": "Admin privileges required"}), 403
        return f(*args, **kwargs)
    return decorated_function

# ✅ Route for Landing Page
@main_bp.route('/')
def home():
    return render_template('landing.html')  # ✅ Ensures landing.html is rendered first

# ✅ Route for Viewing All Threats
@main_bp.route('/threat')
def threat_reports():
    threats = ThreatReport.query.all()
    return render_template('report.html', threats=threats)  # ✅ Display threats properly

@main_bp.route('/me', methods=['GET'])
@jwt_required()
def about_me():
    user_name = get_jwt_identity()    
    print(user_name)
    user = User.query.filter_by(username=user_name).first()
    if not user:
        return "The user was not found", 404 # TODO : Handle this case here

    return render_template("me.html", user=user)

# ✅ Route for Public Threat View
@main_bp.route('/all', methods=['GET'])
def public_threats():
    threats = ThreatReport.query.all()
    return render_template('threats_public_view.html', threats=threats)

# ✅ Submit Threat Form Handler
@main_bp.route('/submit-threat', methods=['POST'])
@jwt_required(optional=True) 
def submit_threat():
    # Try to fetch user from the JWT that is coming in 
    username = get_jwt_identity()
    user = User.query.filter_by(username=username).first()
    if user:
            organization_id = user.organization_id
            print("Organization ID:", organization_id)  # Debug print to check the organization_id
    else:
        print("User not found for username:", username)
    print(username, user)
        
    # 🔹 Validate Required Fields
    required_fields = ['threat_title', 'summary', 'detailed_description', 'impact_type', 'severity_level']
    for field in required_fields:
        if not request.form.get(field):
            flash(f"{field.replace('_', ' ').capitalize()} is required.", "danger")
            return redirect(url_for('main_bp.threat_reports'))

    # 🔹 Extract Form Data
    threat_title = request.form.get('threat_title')
    summary = request.form.get('summary')
    iocs = request.form.get('iocs', 'None provided')
    affected_platforms = request.form.get('affected_platforms', 'None specified')
    affected_platform_ver = request.form.get('affected_platform_ver', 'None specified')
    affected_service = request.form.get('affected_service', 'None specified')
    affected_service_ver = request.form.get('affected_service_ver', 'None specified')
    detailed_description = request.form.get('detailed_description')
    impact_type = request.form.get('impact_type')
    severity_level = request.form.get('severity_level')
    mitigation_actions = request.form.get('mitigation_actions', 'No actions taken yet')

    # 🔹 Secure File Upload Handling
    attachment = request.files.get('attachment')
    attachment_path = None
    if attachment and attachment.filename:
        upload_folder = os.path.join(current_app.root_path, 'uploads')
        os.makedirs(upload_folder, exist_ok=True)  # Ensure directory exists
        filename = secure_filename(attachment.filename)
        attachment_path = os.path.join(upload_folder, filename)
        attachment.save(attachment_path)

    # 🔹 Create New Threat Report
    threat_report = ThreatReport(
        threat_title=threat_title,
        summary=summary,
        iocs=iocs,
        affected_platforms=affected_platforms,
        detailed_description=detailed_description,
        affected_platform_ver=affected_platform_ver,
        affected_service=affected_service,
        affected_service_ver=affected_service_ver,
        impact_type=impact_type,
        severity_level=severity_level,
        mitigation_actions=mitigation_actions,
        attachment_path=attachment_path,
        username=username
    )

    # 🔹 Database Transaction Handling
    try:
        db.session.add(threat_report)
        db.session.commit()
        flash("Threat report submitted successfully!", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Database error: {str(e)}", "danger")

    return redirect(url_for('main_bp.threat_reports'))

# ✅ Route for FAQ Page
@main_bp.route('/faq')
def faq():
    return render_template('faq.html')  # ✅ Renders the FAQ page

# ✅ Route for Guidelines Page
@main_bp.route('/guidelines')
def guidelines():
    return render_template('guidelines.html')  # ✅ Renders the Guidelines page