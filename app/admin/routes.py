from flask import Blueprint, render_template

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/')
def admin_dashboard():
    return render_template('admin/dashboard.html')

@admin_bp.route('/threats')
def view_threats():
    # Fetch all threat reports from the database
    from app.models import ThreatReport
    threats = ThreatReport.query.all()
    return render_template('admin/threats.html', threats=threats)

@admin_bp.route('/users')
def view_users():
    # Fetch all users
    from app.models import User
    users = User.query.all()
    return render_template('admin/users.html', users=users)
