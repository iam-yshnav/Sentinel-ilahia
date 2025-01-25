import os
import secrets  # for generating random tokens
from flask import request, jsonify, redirect, url_for, flash, render_template
from app import db
from app.auth import auth_bp
from app.models import User

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

        role = 'Pending Approval'
        # Create a normal user
        new_user = User(
            username=username,
            name=name,
            salutation=salutation,
            company=company,
            role=role,
            designation=designation,
            team=team,
            domain=domain
        )
        new_user.set_password(password)

        db.session.add(new_user)
        db.session.commit()

        flash("Registered successfully! You can now login.", "success")
        return redirect(url_for('auth_bp.login'))

    return render_template('register.html')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            # Generate token and store it
            token = secrets.token_hex(16)
            user.token = token
            db.session.commit()

            flash("Login successful! Here is your token.", "success")
            return jsonify({
                "message": "Logged in successfully",
                "token": token,
                "role": user.role
            })
        else:
            flash("Invalid credentials.", "error")
            return redirect(url_for('auth_bp.login'))

    return render_template('login.html')

@auth_bp.route('/logout', methods=['POST'])
def logout():
    token = request.headers.get('Authorization')  # for example: "Bearer <token>"
    if not token:
        return jsonify({"error": "Token not provided"}), 401

    token = token.replace("Bearer ", "")  # Remove "Bearer " prefix if present
    user = User.query.filter_by(token=token).first()
    if not user:
        return jsonify({"error": "Invalid token"}), 401

    # Invalidate the token
    user.token = None  
    db.session.commit()
    return jsonify({"message": "Logged out successfully"})
