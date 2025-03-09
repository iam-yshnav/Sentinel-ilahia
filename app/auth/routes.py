import os
import secrets  # For generating random tokens
from flask import request, jsonify, redirect, url_for, flash, render_template, session, make_response
from app import db
from app.auth import auth_bp
from app.models import Organization, User
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity,
    set_access_cookies, unset_jwt_cookies
)

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        name = request.form.get('name')
        salutation = request.form.get('salutation')
        organization_id = request.form.get('organization_id')  # ✅ Get organization ID from form
        company = request.form.get('company')
        designation = request.form.get('designation')
        team = request.form.get('team')
        domain = request.form.get('domain')

        # Convert organization_id to an integer if selected
        if organization_id and organization_id.isdigit():
            organization_id = int(organization_id)
        else:
            organization_id = None  # Ensure it's None if not selected

        # If organization is selected, ignore company field
        if organization_id:
            company = None  # ✅ Avoid storing both organization and company

        # Check if username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("Username already exists. Choose a different one.", "error")
            return redirect(url_for('auth_bp.register'))

        # Create new user
        new_user = User(
            username=username,
            role='user',
            name=name,
            salutation=salutation,
            organization_id=organization_id,  # ✅ Store organization ID
            company=company,  # ✅ Company is only stored if no organization is selected
            designation=designation,
            team=team,
            domain=domain
        )
        new_user.set_password(password)

        db.session.add(new_user)
        db.session.commit()

        flash("Registered successfully! You can now log in.", "success")
        return redirect(url_for('auth_bp.login'))  # ✅ Redirects to login after successful registration

    # ✅ Fetch organizations from the database and pass them to the template
    organizations = Organization.query.all()
    return render_template('register.html', organizations=organizations)


# 📝 LOGIN ROUTE (MODIFIED ✅)
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        print(username, password)
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            # Generate a token and store it
            access_token = create_access_token(identity=username)
            resp = make_response(redirect(url_for('main_bp.about_me'))) # TODO change this in neat future
            set_access_cookies(resp, access_token)
            return resp
        flash("Invalid credentials. Please try again.", "error")  # ✅ Flash error message
        print("Invalid credentials. Please try again")
        return redirect(url_for('auth_bp.login'))  # ✅ Redirects back to login on failure

    return render_template('login.html')

# 📝 LOGOUT ROUTE
@auth_bp.route('/logout', methods=['POST'])
def logout():
    token = request.headers.get('Authorization')  # "Bearer <token>"
    if not token:
        return jsonify({"error": "Token not provided"}), 401

    token = token.replace("Bearer ", "")  # Remove "Bearer " prefix if present
    user = User.query.filter_by(token=token).first()
    if not user:
        return jsonify({"error": "Invalid token"}), 401 
    # Invalidate the token
    user.token = None
    db.session.commit()
    session.pop('user_id', None)  # Remove user session

    flash("Logged out successfully.", "success")
    return redirect(url_for('auth_bp.login'))  

# 📝 COMPANY LOGIN ROUTE
@auth_bp.route('/companylogin', methods=['GET', 'POST'])
def companylogin():
    return render_template('companylogin.html')

