from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import os

db = SQLAlchemy()
migrate = Migrate()

def create_app():
    app = Flask(__name__, instance_relative_config=True)
    

    app.config.from_object('app.config.Config')
    
    app.secret_key = app.config.get('SECRET_KEY', 'valare_rahasyamaya_oru_sambhavam_ann_ith')
    
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    db.init_app(app) # db ivide init avum
    migrate.init_app(app, db)
    from app.main.routes import main_bp
    app.register_blueprint(main_bp)
    
    return app
