from flask import request, jsonify
from app import db
from app.models import Organization, User, Asset
from flask_jwt_extended import jwt_required, create_access_token, get_jwt_identity


from app.org import org_bp

# TODO : Add auth stuff
@org_bp.route('/create', methods=['POST'])
def create_organiztion():
    current_user = 'check_admin' 
    data = request.get_json()

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

