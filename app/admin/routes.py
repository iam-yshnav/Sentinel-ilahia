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
    # Ensure default organization exists for normal users
    default_org = Organization.query.filter_by(name='Individual Users').first()
    if not default_org:
        default_org = Organization(
            name='Individual Users', 
            industry='General',
            is_banned=False
        )
        db.session.add(default_org)
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            flash(f"Error creating default organization: {e}", "danger")

    # Get users sorted by role
    return render_template(
        'admin_user.html',
        admin_users=User.query.filter_by(role='admin').all(),
        company_users=User.query.filter_by(role='company').all(),
        normal_users=User.query.filter_by(role='normal').all(),
        default_org=default_org
    )

@admin_bp.route('/admin/user/approve', methods=['POST'])
def approve_user():
    user_id = request.form.get('user_id')
    user = User.query.get_or_404(user_id)
    
    # Organization handling based on role
    if user.role == 'company':
        org_id = request.form.get('organization_id')
        organization = Organization.query.get(org_id)
        if not organization:
            flash("Company organization not found", "danger")
            return redirect(url_for('admin.admin_users'))
            
    elif user.role == 'normal':
        organization = Organization.query.filter_by(name='Individual Users').first()
        if not organization:
            flash("Default organization missing! Contact admin", "danger")
            return redirect(url_for('admin.admin_users'))
            
    else:  # admin
        organization = None

    # Update user state
    if user.status == 'approved':
        flash(f"{user.role.capitalize()} user already approved", "warning")
    else:
        try:
            if user.role != 'admin':
                user.organization = organization
            user.status = 'approved'
            db.session.commit()
            flash(f"{user.role.capitalize()} user approved successfully", "success")
        except Exception as e:
            db.session.rollback()
            flash(f"Approval failed: {str(e)}", "danger")

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

@admin_bp.route('/admin/rewards')
def admin_rewards():
    severity_weights = {
        'low': 1,
        'medium': 2,
        'high': 3,
        'critical': 5
    }

    users = User.query.filter(User.role.in_(['normal', 'company'])).all()
    all_users_data = []

    for user in users:
        reports = ThreatReport.query.filter_by(username=user.username, approved=True).all()
        counts = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
        total_score = 0

        for r in reports:
            level = r.severity_level.lower() if r.severity_level else 'low'
            if level in counts:
                counts[level] += 1
                total_score += severity_weights[level]

        all_users_data.append({
            'id': user.id,
            'username': user.username,
            'name': user.name or user.username,
            'role': user.role,
            'total_score': total_score,
            'token': user.token,
            'low': counts['low'],
            'medium': counts['medium'],
            'high': counts['high'],
            'critical': counts['critical'],
        })

    return render_template('admin_rewards.html', all_users=all_users_data)


@admin_bp.route('/admin/user/update_token', methods=['POST'])
def update_user_token():
    user_id = request.form.get('user_id')
    token_value = request.form.get('token_value')
    token_action = request.form.get('token_action', 'add')

    user = User.query.get(user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('admin.admin_rewards'))

    try:
        token_value = int(token_value)
        if token_action == 'subtract':
            user.token = max(0, (user.token or 0) - token_value)
            flash(f"Removed {token_value} token(s) from {user.username}. Current total: {user.token}", "danger")
        else:
            user.token = (user.token or 0) + token_value
            flash(f"Added {token_value} token(s) to {user.username}. Current total: {user.token}", "success")

        db.session.commit()

    except Exception as e:
        db.session.rollback()
        flash(f"Error updating token: {str(e)}", "danger")

    return redirect(url_for('admin.admin_rewards'))
