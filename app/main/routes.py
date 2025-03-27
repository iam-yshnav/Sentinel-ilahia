from flask import render_template, request, redirect, url_for, flash, jsonify, current_app
from werkzeug.utils import secure_filename
from functools import wraps
from app.models import Asset, Organization, ThreatIntelligence, User, ThreatReport
import os
from flask_jwt_extended import get_jwt_identity, jwt_required
from app import db
from app.main import main_bp

from flask import Blueprint, render_template, make_response
from weasyprint import HTML

from .comp import add_vulnerable_assets_to_threat_intel

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
    user = User.query.filter_by(username=user_name).first()

    if not user:
        return "The user was not found", 404

    # Fetch threats submitted by the logged-in user
    user_threats = ThreatReport.query.filter_by(username=user_name).all()

    # Fetch assets submitted by the logged-in user
    user_assets = Asset.query.filter_by(organization_id=user.organization_id).all()

    # Fetch threats related to the user's assets
    asset_threats = []
    for asset in user_assets:
        threats = ThreatReport.query.filter_by(affected_service=asset.service_name).all()
        asset_threats.extend(threats)

    return render_template(
        "me.html",
        user=user,
        user_threats=user_threats,
        user_assets=user_assets,
        asset_threats=asset_threats
    )


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
    
    add_vulnerable_assets_to_threat_intel(threat_report)


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

@main_bp.route('/threat_intelligence/<int:intel_id>/pdf')
def generate_pdf(intel_id):
    try:
        # Fetch the threat intelligence entry
        threat_intel = db.session.get(ThreatIntelligence, intel_id)
        if not threat_intel:
            return jsonify({"error": "Threat Intelligence entry not found"}), 404

        # Get related threat report
        threat = db.session.get(ThreatReport, threat_intel.threat_id)
        if not threat:
            return jsonify({"error": "Threat Report not found"}), 404

        # Get related asset
        asset = db.session.get(Asset, threat_intel.asset_id)
        if not asset:
            return jsonify({"error": "Asset not found"}), 404

        # Get organization details if available
        organization = db.session.get(Organization, asset.organization_id) if asset.organization_id else None

        # Prepare data for rendering
        html_content = render_template("threat_pdf.html",
    # Threat Overview
    threat_title=threat.threat_title,  # Change 'threat_name' → 'threat_title'
    severity_level=threat.severity_level,  # Change 'severity' → 'severity_level'
    impact_type=threat.impact_type or "Unknown",
    detailed_description=threat.detailed_description or "No description available",  # Change 'description' → 'detailed_description'
    iocs=threat.iocs or "No IOCs provided",
    affected_platforms=threat.affected_platforms or "Unknown",
    affected_platform_ver=threat.affected_platform_ver or "Unknown",
    affected_service=threat.affected_service or "Unknown",
    affected_service_ver=threat.affected_service_ver or "Unknown",
    mitigation_actions=threat.mitigation_actions or "No mitigation steps provided",
    attachment_path=threat.attachment_path or "No attachment",

    # Asset Details
    server_name=asset.server_name,  # Change 'asset_name' → 'server_name'
    ip_address=asset.ip_address,
    os_name=asset.os_name,
    os_version=asset.os_version,
    service_name=asset.service_name,
    service_version=asset.service_version,
    server_purpose=asset.server_purpose,
    cpu_configuration=f"{asset.cpu_configuration} Cores",
    ram_capacity=f"{asset.ram_capacity} GB",
    storage_configuration=asset.storage_configuration or "No details",
    network_configuration=asset.network_configuration or "No details",
    security_protocols=asset.security_protocols or "No details",
    admin_contact=asset.admin_contact,

    # Organization Information
    organization_name=organization.name if organization else "Unknown",
    industry=organization.industry if organization else "Not Specified",

    # Additional Information
    state=threat_intel.state,  
    last_scanned=threat_intel.created_at.strftime('%Y-%m-%d %H:%M:%S')
)

        # Convert the HTML to PDF
        pdf_bytes = HTML(string=html_content).write_pdf()

        # Return the PDF as a response
        response = make_response(pdf_bytes)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'inline; filename="threat_intelligence_{intel_id}.pdf"'
        
        return response
    except Exception as e:
        return jsonify({"error": str(e)}), 500