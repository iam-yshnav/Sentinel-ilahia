import os
import secrets  # For generating random tokens
from flask import request, jsonify, redirect, url_for, flash, render_template, session
from app import db
from app.auth import auth_bp
from app.models import User

# 📝 REGISTER ROUTE
@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        name = request.form.get('name')
        salutation = request.form.get('salutation')
        company = request.form.get('company')
        designation = request.form.get('designation')
        team = request.form.get('team')
        domain = request.form.get('domain')

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
            company=company,
            designation=designation,
            team=team,
            domain=domain
        )
        new_user.set_password(password)

        db.session.add(new_user)
        db.session.commit()

        flash("Registered successfully! You can now log in.", "success")
        return redirect(url_for('auth_bp.login'))  # ✅ Redirects to login after successful registration

    return render_template('register.html')

# 📝 LOGIN ROUTE (MODIFIED ✅)
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            # Generate a token and store it
            token = secrets.token_hex(16)
            user.token = token
            db.session.commit()

            session['user_id'] = user.id  # Storing user session
            flash("Login successful!", "success")

            return redirect(url_for('all'))  # ✅ Redirects to /all on successful login

        flash("Invalid credentials. Please try again.", "error")  # ✅ Flash error message
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

