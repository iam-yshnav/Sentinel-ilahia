from flask import Blueprint, render_template, request, redirect, url_for, flash
from app.models import ThreatReport, User, Organization
from app import db

admin_bp = Blueprint('admin', __name__)

### 🏠 Admin Dashboard ###
@admin_bp.route('/')
def admin_dashboard():
   
    active_threats = ThreatReport.query.filter_by(deleted=False).all()
    deleted_threats = ThreatReport.query.filter_by(deleted=True).all()  # Fetch deleted threats
    users = User.query.all()  # Fetch all users
    return render_template('admin.html', threats=active_threats, deleted_threats=deleted_threats, users=users)

### 🚨 Threat Management ###
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


# Regarding the Organizations

# Endpoint for adding an organization (GET displays the page, POST processes the form)
@admin_bp.route('/orgs/add', methods=['GET', 'POST'])
def add_organization():
    if request.method == 'POST':
        name = request.form.get('name')
        industry = request.form.get('industry')
        
        if not name:
            flash("Organization name is required.", "danger")
            return redirect(url_for('admin.add_organization'))
        
        # Check if an organization with the same name already exists
        existing_org = Organization.query.filter_by(name=name).first()
        if existing_org:
            flash("Organization already exists.", "danger")
            return redirect(url_for('admin.add_organization'))
        
        # Create and add the new organization
        new_org = Organization(name=name, industry=industry)
        # Assuming the Organization model has an "is_banned" field; initialize as not banned.
        new_org.is_banned = False
        
        try:
            db.session.add(new_org)
            db.session.commit()
            flash("Organization added successfully.", "success")
        except Exception as e:
            db.session.rollback()
            flash(f"Error adding organization: {e}", "danger")
        return redirect(url_for('admin.add_organization'))
    
    # GET request: fetch and display all organizations
    organizations = Organization.query.all()
    return render_template('admin_orgnizations.html', organizations=organizations)


# TODO : Check with the ban stuff 
@admin_bp.route('/orgs/ban/<int:org_id>', methods=['POST'])
def ban_organization(org_id):
    organization = Organization.query.get_or_404(org_id)
    if getattr(organization, 'is_banned', "1"):
        flash("Organization is already banned.", "warning")
    else:
        organization.is_banned = "1"
        try:
            db.session.commit()
            flash("Organization banned successfully.", "success")
        except Exception as e:
            db.session.rollback()
            flash(f"Error banning organization: {e}", "danger")
    return redirect(url_for('admin.add_organization'))


# Endpoint to de-ban (unban) an organization
@admin_bp.route('/orgs/deban/<int:org_id>', methods=['POST'])
def deban_organization(org_id):
    organization = Organization.query.get_or_404(org_id)
    if not getattr(organization, 'is_banned', False):
        flash("Organization is not banned.", "warning")
    else:
        organization.is_banned = False
        try:
            db.session.commit()
            flash("Organization unbanned successfully.", "success")
        except Exception as e:
            db.session.rollback()
            flash(f"Error unbanning organization: {e}", "danger")
    return redirect(url_for('admin.add_organization'))

### 👥 User Management ###

@admin_bp.route('/users')
def admin_users():
    users = User.query.all()
    return render_template('admin_user.html', users=users)

@admin_bp.route('/admin/user/approve', methods=['POST'])
def approve_user():
    user_id = request.form.get('user_id')
    organization_id = request.form.get('organization_id')

    user = User.query.get(user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('admin.admin_users'))

    organization = Organization.query.get(organization_id)
    if not organization:
        flash("Organization not found.", "danger")
        return redirect(url_for('admin.admin_users'))

    if user.organization_id == organization_id and user.status == "approved":
        flash("User is already approved for this organization.", "warning")
    else:
        user.organization_id = organization_id
        user.status = "approved"
        db.session.commit()
        flash(f"User {user_id} approved successfully!", "success")

    return redirect(url_for('admin.admin_users'))

@admin_bp.route('/admin/user/revoke', methods=['POST'])
def revoke_user():
    user_id = request.form.get('user_id')

    user = User.query.get(user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('admin.admin_users'))

    if user.status == "revoked":
        flash("User is already revoked.", "warning")
    else:
        user.status = "revoked"
        db.session.commit()
        flash(f"User {user_id}'s access has been revoked.", "success")

    return redirect(url_for('admin.admin_users'))

@admin_bp.route('/admin/user/ban', methods=['POST'])
def ban_user():
    user_id = request.form.get('user_id')

    user = User.query.get(user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('admin.admin_users'))

    if user.role == "admin":
        flash("Cannot ban an admin!", "danger")
        return redirect(url_for('admin.admin_users'))

    if user.status == "banned":
        flash("User is already banned.", "warning")
    else:
        user.status = "banned"
        db.session.commit()
        flash(f"User {user_id} has been banned from the system.", "success")

    return redirect(url_for('admin.admin_users'))
