import os
import secrets
from flask import request, jsonify, redirect, url_for, flash, render_template, session, make_response
from app import db
from app.auth import auth_bp
from app.models import Organization, User
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity,
    set_access_cookies, unset_jwt_cookies
)

# 📝 REGISTER ROUTE
@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        name = request.form.get('name')
        salutation = request.form.get('salutation')
        organization_id = request.form.get('organization_id')  # Get organization ID from form
        company = request.form.get('company')
        designation = request.form.get('designation')
        team = request.form.get('team')
        domain = request.form.get('domain')
        email = request.form.get('email')  # Add email field

        # Convert organization_id to an integer if selected
        if organization_id and organization_id.isdigit():
            organization_id = int(organization_id)
        else:
            organization_id = None  # Ensure it's None if not selected

        # If organization is selected, ignore company field
        if organization_id:
            company = None  # Avoid storing both organization and company

        # Check if username or email already exists
        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            flash("Username or email already exists. Choose a different one.", "error")
            return redirect(url_for('auth_bp.register'))

        # Create new user with role 'company' if organization_id is provided
        role = 'company' if organization_id else 'normal'
        new_user = User(
            username=username,
            role=role,
            name=name,
            salutation=salutation,
            email=email,
            organization_id=organization_id,
            company=company,
            designation=designation,
            team=team,
            domain=domain,
            status='pending'  # Default status
        )
        new_user.set_password(password)

        db.session.add(new_user)
        db.session.commit()

        flash("Registered successfully! Please wait for admin approval.", "success")
        return redirect(url_for('auth_bp.login'))  # Redirect to login after successful registration

    # Fetch organizations from the database and pass them to the template
    organizations = Organization.query.all()
    return render_template('register.html', organizations=organizations)


# 📝 OTHERS REGISTER ROUTE
@auth_bp.route('/userregister', methods=['GET', 'POST'])
def userregister():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        name = request.form.get('name')
        salutation = request.form.get('salutation')
        email = request.form.get('email')

        # Check if username or email already exists
        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            flash("Username or email already exists. Choose a different one.", "error")
            return redirect(url_for('auth_bp.userregister'))

        # Create new user with role 'normal'
        new_user = User(
            username=username,
            role='normal',
            name=name,
            salutation=salutation,
            email=email,
            status='pending'  # Default status
        )
        new_user.set_password(password)

        db.session.add(new_user)
        db.session.commit()

        flash("Registered successfully! Please wait for admin approval.", "success")
        return redirect(url_for('auth_bp.login'))  # Redirect to login after successful registration

    return render_template('othersregister.html')


# 📝 LOGIN ROUTE
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            if user.status != 'approved':
                flash("Your account is pending approval. Please contact the admin.", "error")
                return redirect(url_for('auth_bp.login'))

            # Generate a token and store it
            access_token = create_access_token(identity=username)
            resp = make_response(redirect(url_for('main_bp.about_me')))  # TODO: Change this in the near future
            set_access_cookies(resp, access_token)
            return resp

        flash("Invalid credentials. Please try again.", "error")
        return redirect(url_for('auth_bp.login'))

    return render_template('login.html')


# 📝 LOGOUT ROUTE
@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    resp = make_response(redirect(url_for('auth_bp.login')))
    unset_jwt_cookies(resp)
    flash("Logged out successfully.", "success")
    return resp




