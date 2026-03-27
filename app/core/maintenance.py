# core/maintenance.py
import os
import shutil
from pathlib import Path
from datetime import datetime
from .models import db, Session, Enrollment, Course, AssessmentForm, User

class MaintenanceUtils:
    @staticmethod
    def perform_data_integrity_check():
        issues = []
        
        # Orphaned enrollments
        orphaned = Enrollment.query.filter(
            ~Enrollment.student_id.in_(db.session.query(User.id))
        ).all()
        if orphaned:
            issues.append({'type': 'Orphaned Enrollments', 'count': len(orphaned)})
        
        # Courses without instructor
        no_instructor = Course.query.filter(Course.instructor_rel == None).all()
        if no_instructor:
            issues.append({'type': 'Courses Without Instructor', 'count': len(no_instructor),
            'details':no_instructor }) 
        return issues
    
    @staticmethod
    def create_backup(app):
        try:
            backup_dir = Path(app.root_path) / 'backups'
            backup_dir.mkdir(exist_ok=True)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_file = backup_dir / f'backup_{timestamp}.db'
            shutil.copy2(
                app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', ''), 
                backup_file
            )
            return str(backup_file)
        except Exception as e:
            return f"Backup failed: {str(e)}"
    
    @staticmethod
    def clean_old_sessions(days=7):
        old_sessions = datetime.utcnow() - timedelta(days=days)
        deleted = Session.query.filter(Session.expiry < old_sessions).delete()
        db.session.commit()
        return deleted