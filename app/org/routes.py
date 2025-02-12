from flask import render_template, request, jsonify
from app import db
from app.models import Organization, User, Asset
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.org import org_bp


@org_bp.route('/')
def server():
    return render_template('server.html')


# Create Organization (Admin Only)
@org_bp.route('/create', methods=['POST'])
@jwt_required()
def create_organization():
    # Get current user from JWT
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)

    # Check if user is admin
    if not current_user or not current_user.is_admin:
        return jsonify({"error": "Unauthorized. Admin access required"}), 403

    # Get data from request
    data = request.get_json()
    if not data or 'name' not in data:
        return jsonify({"error": "Organization name is required"}), 400

    new_org = Organization(
        name=data['name'],
        industry=data.get('industry')
    )

    try:
        db.session.add(new_org)
        db.session.commit()
        return jsonify({
            "message": "Organization created successfully",
            "organization_id": new_org.id
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


# Get All Organizations
@org_bp.route('/list', methods=['GET'])
@jwt_required()
def list_organizations():
    organizations = Organization.query.all()
    org_list = [{"id": org.id, "name": org.name, "industry": org.industry} for org in organizations]
    
    return jsonify({"organizations": org_list}), 200


# Create Asset (Attach to an Organization)
@org_bp.route('/create_asset', methods=['POST'])
@jwt_required()
def create_asset():
    data = request.get_json()
    
    if not data or 'server_name' not in data or 'organization_id' not in data:
        return jsonify({"error": "Server name and organization ID are required"}), 400
    
    org = Organization.query.get(data['organization_id'])
    if not org:
        return jsonify({"error": "Invalid organization ID"}), 404

    new_asset = Asset(
        server_name=data['server_name'],
        ip_address=data.get('ip_address'),
        service_name=data.get('service_name'),
        service_version=data.get('service_version'),
        operating_system=data.get('operating_system'),
        server_purpose=data.get('server_purpose'),
        cpu_configuration=data.get('cpu_configuration'),
        ram_capacity=data.get('ram_capacity'),
        storage_configuration=data.get('storage_configuration'),
        network_configuration=data.get('network_configuration'),
        security_protocols=data.get('security_protocols'),
        admin_contact=data.get('admin_contact'),
        organization_id=data['organization_id']
    )

    try:
        db.session.add(new_asset)
        db.session.commit()
        return jsonify({"message": "Asset created successfully", "asset_id": new_asset.id}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


# Get All Assets for an Organization
@org_bp.route('/organization/<int:org_id>/assets', methods=['GET'])
@jwt_required()
def get_assets_by_organization(org_id):
    org = Organization.query.get(org_id)
    if not org:
        return jsonify({"error": "Organization not found"}), 404

    assets = Asset.query.filter_by(organization_id=org_id).all()
    asset_list = [{
        "id": asset.id,
        "server_name": asset.server_name,
        "ip_address": asset.ip_address,
        "operating_system": asset.operating_system
    } for asset in assets]

    return jsonify({"organization": org.name, "assets": asset_list}), 200
