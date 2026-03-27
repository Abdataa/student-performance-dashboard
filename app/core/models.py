from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import secrets
db = SQLAlchemy()

# ---------------------------
# Database Models
# ---------------------------

class Announcement(db.Model):
    __tablename__ = 'announcements'
    id         = db.Column(db.Integer, primary_key=True)
    author_id  = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    title      = db.Column(db.String(200), nullable=False)
    content    = db.Column(db.Text, nullable=False)
    timestamp  = db.Column(db.DateTime, default=datetime.utcnow)
    author     = db.relationship('User', backref='announcements')


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False) 

    email         = db.Column(db.String(120),unique=True, nullable=False)
    password_hash = db.Column(db.String(128),nullable=False)
    role          = db.Column(db.String(20), nullable=False)
    is_active     = db.Column(db.Boolean,    default=False)
    # new fields:
    department    = db.Column(db.String(100), nullable=True)
    section       = db.Column(db.String(50),  nullable=True)

 #------- //     ---------------------   
class Course(db.Model):
    __tablename__ = 'courses'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    semester_id = db.Column(db.Integer, db.ForeignKey('semesters.id'), nullable=False)
    instructor = db.Column(db.Integer, db.ForeignKey('users.id')) 
   


    department   = db.Column(db.String(100), nullable=False)
    section      = db.Column(db.String(50), nullable=False)

    # Add this relationship
    instructor_rel = db.relationship('User', backref='courses_teaching')
    semester = db.relationship('Semester', backref='courses')
    semester_id = db.Column(db.Integer, db.ForeignKey('semesters.id'), nullable=False)
    semester = db.relationship('Semester', backref='courses')


class Semester(db.Model):           ### NEW
    __tablename__ = 'semesters'
    id        = db.Column(db.Integer, primary_key=True)
    name      = db.Column(db.String(20), nullable=False)  # e.g. "2024/2025 I"
    is_open   = db.Column(db.Boolean, default=False)

class Registration(db.Model):       ### NEW
    __tablename__ = 'registrations'
    id          = db.Column(db.Integer, primary_key=True)
    student_id  = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    semester_id = db.Column(db.Integer, db.ForeignKey('semesters.id'), nullable=False)
    status      = db.Column(db.String(20), default='Pending')  # Pending / Approved / Rejected
    timestamp   = db.Column(db.DateTime, default=datetime.utcnow)
    student     = db.relationship('User', backref='registrations')
    semester    = db.relationship('Semester', backref='registrations') 
    # Add unique constraint
    __table_args__ = (
        db.UniqueConstraint('student_id', 'semester_id', name='_student_semester_uc'),
    )


#----------Enr-------    
class Enrollment(db.Model):         ### NEW
    __tablename__ = 'enrollments'
    id          = db.Column(db.Integer, primary_key=True)
    student_id  = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    course_id   = db.Column(db.Integer, db.ForeignKey('courses.id'), nullable=False)
    semester_id = db.Column(db.Integer, db.ForeignKey('semesters.id'), nullable=False)
    student     = db.relationship('User', backref='enrollments')
    course      = db.relationship('Course', backref='enrollments')
    semester    = db.relationship('Semester', backref='enrollments')   

#----assesment ------form------
class AssessmentForm(db.Model):
    
  
    __tablename__ = 'assessment_forms'
    id             = db.Column(db.Integer, primary_key=True)
    teacher_id     = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    course         = db.Column(db.String(100), nullable=False)
    department     = db.Column(db.String(100), nullable=False)
    section        = db.Column(db.String(50), nullable=False)
    quiz_weight    = db.Column(db.Float, nullable=False)
    test1_weight   = db.Column(db.Float, nullable=False)
    test2_weight   = db.Column(db.Float, nullable=False)
    mid_weight     = db.Column(db.Float, nullable=False)
    project_weight = db.Column(db.Float, nullable=False)
    assign_weight  = db.Column(db.Float, nullable=False)
    final_weight   = db.Column(db.Float, nullable=False)
    timestamp      = db.Column(db.DateTime, default=datetime.utcnow)
    teacher        = db.relationship('User', backref='assessment_forms')



 #------------   ----------#        

class AssessmentResult(db.Model):   ### NEW
    __tablename__ = 'assessment_results'
    id         = db.Column(db.Integer, primary_key=True)
    form_id    = db.Column(db.Integer, db.ForeignKey('assessment_forms.id'), nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    score      = db.Column(db.Float, nullable=False)  # actual score
    form       = db.relationship('AssessmentForm', backref='results')
    student    = db.relationship('User', backref='assessment_results')   

class Attendance(db.Model):
    __tablename__ = 'attendance'
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('courses.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    status = db.Column(db.String(10), nullable=False)  # 'Present' or 'Absent'
    
    student = db.relationship('User', backref='attendance_records')
    course = db.relationship('Course', backref='attendance')#--------

#-------
class SystemConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    config_name = db.Column(db.String(50), unique=True)
    config_value = db.Column(db.JSON)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    action = db.Column(db.String(100))
    details = db.Column(db.Text)
    user = db.relationship('User', backref='audit_logs')

# ---------------------------
# APIToken model definition
class APIToken(db.Model):
    __tablename__ = 'api_tokens'
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(64), unique=True, nullable=False)
    description = db.Column(db.String(200), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_used = db.Column(db.DateTime)
    expires_at = db.Column(db.DateTime)
    permissions = db.Column(db.JSON)  # ['read_grades', 'write_attendance']
    is_active = db.Column(db.Boolean, default=True)

    def generate_token(self):
        self.token = secrets.token_urlsafe(48)
        return self.token  
class Session(db.Model):
    __tablename__ = 'sessions'
    id = db.Column(db.String(255), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    expiry = db.Column(db.DateTime, nullable=False)
    data = db.Column(db.LargeBinary, nullable=True)  # Store session data (pickled or JSON)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(256), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_activity = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user = db.relationship('User', backref='sessions')

