from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from apscheduler.schedulers.background import BackgroundScheduler

db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
csrf = CSRFProtect()
scheduler = BackgroundScheduler()

def create_app():
    app = Flask(__name__)
    
    # Load configuration
    app.config.from_pyfile('config.py')
    
    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    csrf.init_app(app)
    
    # Register blueprints
    from .admin.routes import admin_bp
    from .teacher.routes import teacher_bp
    from .student.routes import student_bp
    from .core.auth import auth_bp
    
    app.register_blueprint(admin_bp)
    app.register_blueprint(teacher_bp)
    app.register_blueprint(student_bp)
    app.register_blueprint(auth_bp)
    
    # Start scheduler
    if not scheduler.running:
        scheduler.start()
    
    # Register template filters
    from .core.utils import grade_letter_filter, time_ago_filter
    app.jinja_env.filters['grade_letter'] = grade_letter_filter
    app.jinja_env.filters['time_ago'] = time_ago_filter
    
    return app