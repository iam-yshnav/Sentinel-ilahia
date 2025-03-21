from flask import render_template, request, jsonify, redirect, url_for, flash
from app import db
from app.models import Organization, User, Asset
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.org import org_bp

# Render the add_asset.html page
@org_bp.route('/asset', methods=['GET'])
@jwt_required()
def add_asset():
    username = get_jwt_identity()
    user = User.query.filter_by(username=username).first()

    # Ensure the user is a company user
    if not user or user.role != 'company':
        flash("Unauthorized access. Only company users can access this page.", "danger")
        return redirect(url_for('main_bp.home'))

    org_id = user.organization_id
    org = Organization.query.get(org_id)
    if not org:
        flash("Organization not found.", "danger")
        return redirect(url_for('main_bp.home'))

    return render_template('add_asset.html', org_id=org_id, org_name=org.name)

# Handle asset creation
@org_bp.route('/create_asset', methods=['POST'])
@jwt_required()
def create_asset():
    username = get_jwt_identity()
    user = User.query.filter_by(username=username).first()

    if not user or user.role != 'company':
        flash("Unauthorized action.", "danger")
        return redirect(url_for('main_bp.home'))

    data = request.get_json()
    org_id = user.organization_id
    org = Organization.query.get(org_id)
    if not org:
        flash("Invalid organization ID.", "danger")
        return redirect(url_for('main_bp.home'))
    new_asset = Asset(
        server_name=data['server_name'],
        os_name=data['os_name'],
        os_version=data.get('os_version', ''),
        ip_address=data['ip_address'],
        service_name=data.get('service_name', ''),
        service_version=data.get('service_version', ''),
        organization_id=data['organization_id'],
        server_purpose=data['server_purpose'],
        cpu_configuration=data['cpu_configuration'],
        ram_capacity=data['ram_capacity'],
        storage_configuration=data.get('storage_configuration', ''),
        network_configuration=data.get('network_configuration', ''),
        security_protocols=data.get('security_protocols', ''),
        admin_contact=data['admin_contact']
    )

    try:
        db.session.add(new_asset)
        db.session.commit()
        return jsonify({"message": "Asset created successfully", "asset_id": new_asset.id}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

# # Fetch assets for an organization
# @org_bp.route('/organization/<int:org_id>/assets', methods=['GET'])
# @jwt_required()
# def get_assets_by_organization(org_id):
#     username = get_jwt_identity()
#     user = User.query.filter_by(username=username).first()

#     if user.organization_id != org_id:
#         return jsonify({"error": "Unauthorized"}), 403

#     org = Organization.query.get(org_id)
#     if not org:
#         return jsonify({"error": "Organization not found"}), 404

#     assets = Asset.query.filter_by(organization_id=org_id).all()
#     asset_list = [{
#         "id": asset.id,
#         "server_name": asset.server_name,
#         "ip_address": asset.ip_address,
#         "os_name": asset.os_name
#     } for asset in assets]

#     return jsonify({"organization": org.name, "assets": asset_list}), 200