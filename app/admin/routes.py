from flask import Blueprint, render_template

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/') # Yet to implement the admin access stuff 
def admin_dashboard():
    from app.models import ThreatReport, User
    threats = ThreatReport.query.all()  # Fetch all threat reports
    users = User.query.all()  # Fetch all users
    return render_template('admin.html', threats=threats, users=users)
    

# @admin_bp.route('/threats')
# def view_threats():
#     # Fetch all threat reports from the database
#     from app.models import ThreatReport
#     threats = ThreatReport.query.all()
#     return render_template('admin.html', threats=threats)

# @admin_bp.route('/users')
# def view_users():
#     # Fetch all users
#     from app.models import User
#     users = User.query.all()
#     return render_template('admin.html', users=users)