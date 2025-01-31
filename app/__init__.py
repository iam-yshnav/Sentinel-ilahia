from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import os
# Init -> Initilizstion -> meaning  if app package is called it will start __init__.py

db = SQLAlchemy() # ORM  https://auth0.com/blog/sqlalchemy-orm-tutorial-for-python-developers/
migrate = Migrate()


def  create_app():
    app = Flask(__name__, instance_relative_config=True)
    

    app.config.from_object('app.config.Config')
    
    app.secret_key = app.config.get('SECRET_KEY', 'valare_rahasyamaya_oru_sambhavam_ann_ith')
    
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    db.init_app(app) # db ivide init avum
    migrate.init_app(app, db)
    from app.main.routes import main_bp
    from app.auth.routes import auth_bp
    from app.admin.routes import admin_bp
    from app.org.routes import org_bp
    
    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(admin_bp, url_prefix='/admin')
    app.register_blueprint(org_bp, url_prefix='/org')

    return app
