from flask import Flask, render_template, request, redirect, url_for, flash, session, current_app, abort
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import joblib
import pandas as pd
from datetime import datetime, timezone
from ML.study_recommendation import generate_recommendation
from flask_wtf.csrf import CSRFProtect, validate_csrf
from flask_migrate import Migrate
from werkzeug.exceptions import HTTPException
from sqlalchemy.exc import SQLAlchemyError




app = Flask(__name__)
csrf = CSRFProtect(app)
app.secret_key = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///student_performance.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False



# Custom Jinja Filters
@app.template_filter('grade_letter')
def grade_letter_filter(score):
    if score >= 90: return 'A'
    elif score >= 80: return 'B'
    elif score >= 70: return 'C'
    elif score >= 60: return 'D'
    else: return 'F'

db = SQLAlchemy(app)
migrate = Migrate(app, db)


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

with app.app_context():
    #db.drop_all()
    db.create_all()
    
    # Create default admin user
  #  default_admin = User(
  #      username='admin',
  #      email='admin@university.edu',
  #      password_hash=generate_password_hash('admin123'),  # #Default password
  #      role='admin',
  #      is_active=True,
  #      department='Administration',
  #      section='A'
  #  )
  #  db.session.add(default_admin)
  #  db.session.commit()


# ---------------------------
# Load ML Models
# ---------------------------
predictor_model = None
classifier_model = None
input_features = ['G1', 'G2', 'failures', 'absences', 'higher', 'studytime', 'age', 'Dalc', 'goout']

def get_predictor_model():
    global predictor_model
    if predictor_model is None:
        predictor_model = joblib.load("ML/light_student_performance_predictor_model.joblib")
    return predictor_model

def get_classifier_model():
    global classifier_model
    if classifier_model is None:
        classifier_model = joblib.load("ML/light_at_risk_classifier_model.joblib")
    return classifier_model

# ---------------------------
# Utility Functions
# ---------------------------
def create_admin_if_missing():
    with app.app_context():
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            new_admin = User(
                username='admin',
                email='admin@university.edu',
                password_hash=generate_password_hash('admin123'),
                role='admin',
                is_active=True
            )
            db.session.add(new_admin)
            db.session.commit()
            print("Default admin created!")

# Call this function during app startup
#create_admin_if_missing()

def encode_inputs(data):
    data['higher'] = 1 if data.get('higher') == 'yes' else 0
    return data

def get_config(name, default=None):
    config = SystemConfig.query.filter_by(config_name=name).first()
    return config.config_value if config else default

def set_config(name, value):
    config = SystemConfig.query.filter_by(config_name=name).first()
    if config:
        config.config_value = value
    else:
        config = SystemConfig(config_name=name, config_value=value)
        db.session.add(config)
    db.session.commit()
#-----audit logging decorator------------    
def log_activity(action):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            result = f(*args, **kwargs)
            if current_user.is_authenticated:
                log = AuditLog(
                    user_id=current_user.id,
                    action=action,
                    details=f"Accessed {request.path}"
                )
                db.session.add(log)
                db.session.commit()
            return result
        return wrapper
    return decorator

# Role-based decorator

# Replace both role_required definitions with this:
def roles_required(*required_roles):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if session.get('role') not in required_roles:
                flash('Access denied. Insufficient privileges', 'danger')
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return wrapped
    return decorator





# Add this decorator to your Utility Functions section
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

   
    

# ---------------------------
# Authentication (username-based)
# ---------------------------
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        # Allow admin login even if not active (emergency override)
        if user and user.role == 'admin':
            if check_password_hash(user.password_hash, password):
                session.update(user_id=user.id, role=user.role, username=user.username)
                flash('Admin login successful', 'success')
                return redirect(url_for('dashboard_admin'))
        
        # Normal user validation
        if not user or not check_password_hash(user.password_hash, password):
            flash('Invalid credentials','danger')
            return redirect(url_for('login'))
        if not user.is_active:
            flash('Account pending approval','warning')
            return redirect(url_for('login'))
        
        session.update(user_id=user.id, role=user.role, username=user.username)
        flash('Login successful','success')
        return redirect(url_for(f'dashboard_{user.role}'))
    return render_template('login.html')



@app.route('/logout')
def logout():
    session.clear(); flash('Logged out','info'); return redirect(url_for('login'))

# ---------------------------
# Dashboard Routes
# ---------------------------
@app.route('/dashboard/student')
@roles_required('student')
def dashboard_student():
    # show pending and approved registrations
    regs = Registration.query.filter_by(student_id=session['user_id']).all()
    user = User.query.get(session['user_id'])
    student_name = user.username if user else "Student" # Fallback name
    return render_template('dashboard_student.html', regs=regs,name=student_name)

@app.route('/dashboard/teacher')
@roles_required('teacher')
def dashboard_teacher():
    return render_template('dashboard_teacher.html', name=session.get('username'))


# Audit Logs Route
@app.route('/admin/audit-logs')
@roles_required('admin')
def audit_logs():
    page = request.args.get('page', 1, type=int)
    pagination = AuditLog.query.order_by(AuditLog.timestamp.desc()).paginate(page=page, per_page=20)
    return render_template('audit_logs.html', pagination=pagination)
# System Backup Route
@app.route('/admin/system-backup', methods=['GET', 'POST'])
@roles_required('admin')
def system_backup():
    if request.method == 'POST':
        # Add actual backup implementation
        flash('Backup created successfully', 'success')
        return redirect(url_for('system_backup'))
    return render_template('system_backup.html')

# Email Templates Route
@app.route('/admin/email-templates', methods=['GET', 'POST'])
@roles_required('admin')
def email_templates():
    if request.method == 'POST':
        # Add email template saving logic
        flash('Email templates updated', 'success')
        return redirect(url_for('email_templates'))
    return render_template('email_templates.html')

#
#    ##########
# 
#@app.route('/registrar/toggle-user/<int:user_id>', methods=#['POST'])
#@roles_required('registrar')
#def toggle_user(user_id):


###---/\------------





# ---------------------------
# Semester Management (Registrar/Admin)
# ---------------------------
#toggle semester

  


@app.route('/my-courses')
@roles_required('student')
def my_courses():
    student_id = session['user_id']
    current_semester = Semester.query.filter_by(is_open=True).first()

    # Get all approved registrations
    registrations = Registration.query.filter_by(
        student_id=student_id,
        status='Approved'
    ).join(Semester).order_by(Semester.name.desc()).all()

    # Get selected semester or use current
    selected_sem_id = request.args.get('semester_id', current_semester.id if current_semester else None)
    
    courses_data = []
    if selected_sem_id:
        # Get enrollments for selected semester
        enrollments = Enrollment.query.filter_by(
            student_id=student_id,
            semester_id=selected_sem_id
        ).join(Course).all()

        # Build course details
        for enroll in enrollments:
            course = enroll.course
            instructor = course.instructor_rel

            courses_data.append({
                'course': course,
                'instructor': instructor,
                'schedule': f"{course.days} {course.time}",
                'room': course.room_number,
                'announcements': Announcement.query.filter_by(
                    course_id=course.id
                ).order_by(Announcement.timestamp.desc()).limit(3).all()
            })

    return render_template(
        'my_courses.html',
        registrations=registrations,
        current_semester=current_semester,
        selected_sem_id=selected_sem_id,
        courses_data=courses_data
    )


#---student see their instructors and attendance---------#
@app.route('/my-instructors')
@roles_required('student')
def my_instructors():
    student_id = session['user_id']
    
    enrollments = Enrollment.query.filter_by(student_id=student_id)\
        .join(Course, Enrollment.course_id == Course.id)\
        .options(db.joinedload(Enrollment.course))\
        .all()
    
    instructor_data = []
    
    for enroll in enrollments:
        course = enroll.course
        if not course or not course.instructor:
            continue
            
        instructor = course.instructor_rel  # Use the relationship
        
        instructor_data.append({
            'course': course,
            'instructor': instructor,
            'attendance': Attendance.query.filter_by(
                student_id=student_id,
                course_id=course.id
            ).order_by(Attendance.date.desc()).all(),
            'assessments': AssessmentForm.query.filter_by(
                course=course.name,
                department=course.department,
                section=course.section
            ).all()
        })
    
    return render_template('student_instructors.html', instructor_data=instructor_data)
    
#-------time ago filter-----#
@app.template_filter('time_ago')
def time_ago_filter(dt):
    now = datetime.now(timezone.utc)
    diff = now - dt
    if diff.days > 365:
        return f"{diff.days // 365} years ago"
    if diff.days > 30:
        return f"{diff.days // 30} months ago"
    if diff.days > 0:
        return f"{diff.days} days ago"
    if diff.seconds > 3600:
        return f"{diff.seconds // 3600} hours ago"
    if diff.seconds > 60:
        return f"{diff.seconds // 60} minutes ago"
    return "Just now"    

# ---------------------------
# Approve Semester Registrations (Admin)
# ---------------------------
@app.route('/registrations/semester')
@roles_required('admin', 'registrar')  # Correct decorator name
def semester_registrations():
    regs = Registration.query.filter_by(status='Pending').all()
    return render_template('semester_regs.html', regs=regs)


 ##approval route   
@app.route('/registrations/semester/<int:reg_id>/approve', methods=['POST'])
@roles_required('admin', 'registrar')
def approve_semester(reg_id):
    registration = Registration.query.get_or_404(reg_id)
    registration.status = 'Approved'
    
    # Get all courses for this semester in student's department/section
    courses = Course.query.filter_by(
        semester_id=registration.semester_id,
        department=registration.student.department,
        section=registration.student.section
    ).all()

    # Create enrollments
    for course in courses:
        enrollment = Enrollment(
            student_id=registration.student_id,
            course_id=course.id,
            semester_id=registration.semester_id
        )
        db.session.add(enrollment)

    db.session.commit()
    flash('Registration approved and courses enrolled', 'success')
    return redirect(url_for('semester_registrations'))

@app.route('/registrations/semester/<int:reg_id>/reject', methods=['POST'])
@roles_required('admin', 'registrar')  # Correct decorator name
def reject_semester(reg_id):
    r = Registration.query.get_or_404(reg_id)
    db.session.delete(r)
    db.session.commit()
    flash('Registration rejected', 'info')
    return redirect(url_for('semester_registrations'))


def redirect_back(default='/', **kwargs):
    """
    Redirect to the previous page or a default URL.
    """
    target = request.referrer or default
    return redirect(target)



#
## route to  Semester Management 
#@app.route('/semesters/add', methods=['GET', 'POST'])
#@roles_required('registrar')
#def add_semester():
#    if request.method == 'POST':
#        sem = Semester(
#            name=request.form['name'],
#            is_open=False  # New semesters are closed by default
#        )
#        db.session.add(sem)
#        db.session.commit()
#        flash('Semester created successfully', 'success')
#        return redirect(url_for('dashboard_registrar'))
#    return render_template('add_semester.html')

# filter by section and department----------
@app.route('/registrar/students', methods=['GET', 'POST'])
@roles_required('registrar')
def manage_students():
    # Get distinct departments and sections
    departments = db.session.query(User.department).distinct().filter(User.role == 'student').all()
    sections = db.session.query(User.section).distinct().filter(User.role == 'student').all()

    selected_dept = request.form.get('department') or request.args.get('department')
    selected_section = request.form.get('section') or request.args.get('section')

    students = []
    courses = []
    
    if selected_dept and selected_section:
        # Get students
        students = User.query.filter_by(
            role='student',
            department=selected_dept,
            section=selected_section
        ).all()

        # Get courses for the selected department/section
        courses = Course.query.filter_by(
            department=selected_dept,
            section=selected_section
        ).all()
    teachers = User.query.filter_by(role='teacher').all()    

    return render_template('manage_students.html',
                         departments=departments,
                         sections=sections,
                         selected_dept=selected_dept,
                         selected_section=selected_section,
                         students=students,
                         courses=courses,
                          teachers=teachers)  # Add courses to context
@app.route('/assign-instructor', methods=['POST'])
@roles_required('registrar','admin')
def assign_instructor():
    try:
        # CSRF validation is now automatic
        course_id = request.form['course_id']
        instructor_username = request.form['instructor']

        # Case-insensitive search
        course = Course.query.get_or_404(course_id)
        instructor = User.query.filter(
            db.func.lower(User.username) == instructor_username.strip().lower(),
            User.role == 'teacher'
        ).first_or_404()

        if course.instructor and course.instructor.lower() == instructor.username.lower():
            flash(f'{instructor.username} already assigned', 'info')
            return redirect_back()

        course.instructor = instructor.username
        db.session.commit()
        flash('Assignment successful!', 'success')

    except Exception as e:
        db.session.rollback()
        flash(f'Error: {str(e)}', 'danger')
        app.logger.error(f'Assignment error: {str(e)}')

    return redirect_back()
#---------
# Enrollment Assignment
# ---------------------------
@app.route('/admin/enroll', methods=['GET','POST'])
@roles_required('admin')
def enroll_students():
    if request.method=='POST':
        student_id = request.form['student_id']
        course_id  = request.form['course_id']
        sem_id     = request.form['semester_id']
        e = Enrollment(student_id=student_id, course_id=course_id, semester_id=sem_id)
        db.session.add(e); db.session.commit()
        flash('Student enrolled','success')
        return redirect(url_for('enroll_students'))
    students = User.query.filter_by(role='student', is_active=True).all()
    courses  = Course.query.all()
    semesters= Semester.query.all()
    return render_template('enroll_students.html',
                            students=students, courses=courses, semesters=semesters)

# ---------------------------
# Transcript View
# ---------------------------
##@app.route('/transcript/<int:sem_id>')




@app.route('/profile')
@login_required # any logged-in user
def profile():
    user = User.query.get(session['user_id'])
    return render_template('profile.html', user=user)    
# Student Prediction Input Form
@app.route('/predict-form')
@roles_required('student')
def predict_form():
    return render_template('predict_form.html')

# ---------------------------
# Admin Routes
# ---------------------------
@app.route('/admin-stats')
@roles_required('admin')
def admin_stats():
    total_users = User.query.count()
    role_counts = dict(db.session.query(User.role, db.func.count(User.id)).group_by(User.role).all())
    risk_data   = {'at_risk': 34, 'not_at_risk': 66}
    return render_template('admin_stats.html', total_users=total_users, role_counts=role_counts, risk_data=risk_data)

@app.route('/user-management')
@roles_required('admin')
def user_management():
    page = request.args.get('page', 1, type=int)
    per_page = 10  # Number of users per page
    users = User.query.paginate(page=page, per_page=per_page)
    return render_template('user_management.html', users=users.items, pagination=users)
@app.route('/registrations')
@roles_required('admin')
def registrations():
    page = request.args.get('page', 1, type=int)
    pending = User.query.filter_by(role='student', is_active=False).paginate(page=page, per_page=10)  # 10 users per page
    return render_template('registrations.html', pending=pending.items, pagination=pending)
    pending = User.query.filter_by(role='student', is_active=False).all()
    return render_template('registrations.html', pending=pending)
@app.route('/approve/<int:user_id>', methods=['POST'])
@roles_required('admin')
def approve(user_id):
    try:
        with db.session.begin_nested():  # Use a transaction to ensure atomicity
            user = User.query.with_for_update().get(user_id)  # Lock the row for update
            if user and user.role == 'student' and not user.is_active:
                user.is_active = True
                db.session.commit()
                flash('Registration approved.', 'success')
            else:
                flash('Invalid request.', 'danger')
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'danger') 


@app.route('/reject/<int:user_id>', methods=['GET', 'POST'])
@roles_required('admin')
def reject(user_id):
    user = User.query.get(user_id)
    if request.method == 'POST':
        if user and user.role == 'student' and not user.is_active:
            db.session.delete(user)
            db.session.commit()
            flash('Registration rejected.', 'info')
        else:
            flash('Invalid request.', 'danger')
        return redirect(url_for('registrations'))
    return render_template('confirm_reject.html', user=user)

# --- Admin: Add Registrar ---
@app.route('/admin/add-registrar', methods=['GET','POST'])
@roles_required('admin')
def add_registrar():
    if request.method == 'POST':
        username = request.form['username']
        email    = request.form['email']
        password = request.form['password']
        # always role='registrar'
        hashed_pw = generate_password_hash(password)
        user = User(username=username, email=email,
                    password_hash=hashed_pw, role='registrar',
                    is_active=True)  # active by default
        db.session.add(user)
        db.session.commit()
        flash('Registrar account created!', 'success')
        return redirect(url_for('dashboard_admin'))
    return render_template('add_registrar.html')


# --- Admin: Add or Edit Any User ---
@app.route('/admin/add-user', methods=['GET','POST'])
@roles_required('admin')
def admin_add_user():
    if request.method == 'POST':
        # collect form inputs
        username   = request.form['username']
        email      = request.form['email']
        password   = request.form['password']
        role       = request.form['role']        # e.g. student/teacher/registrar
        department = request.form.get('department')
        section    = request.form.get('section')
        # create & save
        new = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            role=role,
            is_active=True,
            department=department,
            section=section
        )
        db.session.add(new)
        db.session.commit()
        flash(f'{role.capitalize()} created!', 'success')
        return redirect(url_for('user_management'))
    return render_template('admin_add_user.html')

@app.route('/admin/edit-user/<int:user_id>', methods=['GET','POST'])
@roles_required('admin')
def admin_edit_user(user_id):
    u = User.query.get_or_404(user_id)
    if request.method=='POST':
        u.username   = request.form['username']
        u.email      = request.form['email']
        u.role       = request.form['role']
        u.department = request.form.get('department')
        u.section    = request.form.get('section')
        u.password =request.form['password']
        db.session.commit()
        flash('User updated!', 'success')
        return redirect(url_for('user_management'))
    return render_template('admin_edit_user.html', u=u)

@app.route('/admin/delete-user/<int:user_id>', methods=['POST'])
@roles_required('admin')
def admin_delete_user(user_id):
    u = User.query.get_or_404(user_id)
    db.session.delete(u)
    db.session.commit()
    flash('User deleted.', 'info')
    return redirect(url_for('user_management'))
##############

@app.route('/manage-semesters')
@roles_required('admin', 'registrar')
def manage_semesters():
    semesters = Semester.query.order_by(Semester.name.desc()).all()
    return render_template('manage_semesters.html', semesters=semesters)

@app.route('/semesters/toggle/<int:sem_id>', methods=['POST'])
@roles_required('admin', 'registrar')
def toggle_semester(sem_id):
    sem = Semester.query.get_or_404(sem_id)
    sem.is_open = not sem.is_open
    db.session.commit()
    flash(f"{sem.name} is now {'open' if sem.is_open else 'closed'}", "info")
    return redirect(url_for('manage_semesters'))

@app.route('/semesters/add', methods=['GET', 'POST'])
@roles_required('admin', 'registrar')
def add_semester():
    if request.method == 'POST':
        try:
            # Create semester (not committed yet)
            sem = Semester(
                name=request.form['name'],
                is_open=True
            )
            db.session.add(sem)
            
            # Add courses within the same transaction
            course_count = int(request.form['course_count'])
            for i in range(1, course_count + 1):
                course = Course(
                    name=request.form[f'course_{i}_name'],
                    department=request.form[f'course_{i}_dept'],
                    section=request.form[f'course_{i}_section'],
                    instructor=int(request.form[f'course_{i}_instructor']),  # Convert to int
                    semester_id=sem.id
                )
                db.session.add(course)
            
            # Single commit for both semester and courses
            db.session.commit()
            flash('Semester and courses created successfully', 'success')
            return redirect(url_for('manage_semesters'))
        
        except Exception as e:
            db.session.rollback()  # Rollback on error
            flash('Error creating semester: ' + str(e), 'error')
    
    teachers = User.query.filter_by(role='teacher').all()
    return render_template('add_semester.html', teachers=teachers)
# ---------------------------
# Close Semester
# ---------------------------
@app.route('/semesters/close/<int:sem_id>', methods=['POST'])
@roles_required('admin', 'registrar')
def close_semester(sem_id):
    sem = Semester.query.get_or_404(sem_id)
    sem.is_open = False
    db.session.commit()
    flash(f"{sem.name} has been closed", "info")
    return redirect(url_for('manage_semesters'))

# ---------------------------
# Updated Student Registration
# ---------------------------
@app.route('/register-semester', methods=['GET','POST'])
@roles_required('student')
def register_semester():
    student_id = session['user_id']
    open_sems = Semester.query.filter_by(is_open=True).all()
    
    if request.method == 'POST':
        sem_id = request.form.get('semester_id')
        semester = Semester.query.get(sem_id)
        
        if not semester or not semester.is_open:
            flash('Invalid semester selection', 'danger')
            return redirect(url_for('register_semester'))
         
        
        # Existing check and registration logic remains same
        # ...
        # Existing registration check
        existing_reg = Registration.query.filter_by(
            student_id=student_id,
            semester_id=sem_id
        ).first()
        
        if existing_reg:
            flash(f'Registration for {semester.name} already exists', 'warning')
            return redirect(url_for('dashboard_student'))
        
        # Create new registration
        reg = Registration(
            student_id=student_id,
            semester_id=sem_id,
            status='Pending'
        )
        db.session.add(reg)
        db.session.commit()
        flash('Registration submitted for approval', 'success')
        return redirect(url_for('dashboard_student'))
    return render_template('register_semester.html',
                         semesters=open_sems,
                         current_registrations=Registration.query.filter_by(student_id=student_id).all())

# ---------------------------
# Transcript View (Includes closed semesters)
# ---------------------------
@app.route('/transcript')
@roles_required('student')
def transcript():
    student_id = session['user_id']
    semesters = Semester.query.join(Registration).filter(
        Registration.student_id == student_id,
        Registration.status == 'Approved'
    ).all()
    
    return render_template('transcript.html', semesters=semesters)

# ---------------------------
# Registrar Access Control
# ---------------------------
def prevent_admin_modification(user_id):
    target_user = User.query.get(user_id)
    if not target_user:
        flash('User does not exist', 'danger')
        return True
    if target_user.role == 'admin':
        flash('Admin users cannot be modified', 'danger')
        return True
    return False

@app.route('/registrar/toggle-user/<int:user_id>', methods=['POST'])
@roles_required('registrar')
def toggle_user(user_id):
    if prevent_admin_modification(user_id):
        return redirect_back()
    # Original toggle logic
    user = User.query.get_or_404(user_id)
    user.is_active = not user.is_active
    db.session.commit()
    flash(f"{user.username} is now {'Active' if user.is_active else 'Inactive'}.", 'info')
    return redirect(url_for('dashboard_registrar'))




    # Original delete logic






###sem and toggle





# --- Admin: Manage Courses ---

@app.route('/manage-courses')
@roles_required('admin')
def manage_courses():
    courses = Course.query.order_by(Course.department, Course.section, Course.name).all()
    return render_template('manage_courses.html', courses=courses)

@app.route('/manage-courses/add', methods=['GET','POST'])
@roles_required('admin')
def add_course():
    if request.method=='POST':
        c = Course(
            name       = request.form['name'],
            department = request.form['department'],
            section    = request.form['section'],
            instructor = request.form.get('instructor') or None
        )
        db.session.add(c)
        db.session.commit()
        flash('Course added!', 'success')
        return redirect(url_for('manage_courses'))
    return render_template('add_course.html')

@app.route('/manage-courses/edit/<int:course_id>', methods=['GET','POST'])
@roles_required('admin')
def edit_course(course_id):
    c = Course.query.get_or_404(course_id)
    if request.method=='POST':
        c.name       = request.form['name']
        c.department = request.form['department']
        c.section    = request.form['section']
        c.instructor = request.form.get('instructor') or None
        db.session.commit()
        flash('Course updated!', 'success')
        return redirect(url_for('manage_courses'))
    return render_template('edit_course.html', course=c)


@app.route('/manage-courses/delete/<int:course_id>', methods=['POST'])
@roles_required('admin')
def delete_course(course_id):
    c = Course.query.get_or_404(course_id)
    db.session.delete(c)
    db.session.commit()
    flash('Course deleted.', 'info')
    return redirect(url_for('manage_courses'))


# --- Admin Routes: Assessment Form Management ---
@app.route('/admin/assessment-forms')
@roles_required('admin')
def admin_assessment_forms():
    forms = AssessmentForm.query.all()
    return render_template('admin_assessment_forms.html', forms=forms)
# #----admin delete created assessment-form-------
#@app.route('/admin/delete-form/<int:form_id>', methods=['POST'])
#@roles_required('admin')
#def delete_assessment_form(form_id):
#    form = AssessmentForm.query.get(form_id)
#    if form:
#        db.session.delete(form)
#        db.session.commit()
#        flash('Assessment form deleted successfully.', 'success')
#    else:
#        flash('Form not found.', 'danger')
#    return redirect(url_for('admin_assessment_forms'))  


    #---- admin edit assesmnt form----------



#--------------------------------------------------
#             /\___/\
#-------------------------------------------------
@app.route('/admin/system-settings', methods=['GET', 'POST'])
@roles_required('admin')
def system_settings():
    if request.method == 'POST':
        # Update configuration in database or config store
        new_config = {
            'site_name': request.form.get('site_name'),
            'allow_registrations': 'allow_registrations' in request.form,
            'default_role': request.form.get('default_role'),
            'max_courses': int(request.form.get('max_courses', 5)),
            'grade_scale': {
                'A': int(request.form.get('grade_a')),
                'B': int(request.form.get('grade_b')),
                'C': int(request.form.get('grade_c')),
                'D': int(request.form.get('grade_d'))
            }
        }
        # Save to database or config file
        flash('Settings updated successfully', 'success')
        return redirect(url_for('system_settings'))
    
    # Load current configuration
    current_config = {
        'site_name': 'Student Performance System',
        'allow_registrations': True,
        'default_role': 'student',
        'max_courses': 5,
        'grade_scale': {'A': 90, 'B': 80, 'C': 70, 'D': 60}
    }
    return render_template('system_settings.html', config=current_config)

# ---------------------------
# Admin Analytics Routes
# ---------------------------
@app.route('/admin/risk-students')
@roles_required('admin')
def risk_students():
    # Get at-risk students using ML model
    students = User.query.filter_by(role='student').all()
    at_risk = []
    
    for student in students:
        # Get student data and make prediction
        # (Implement your actual risk prediction logic here)
        if student.id % 5 == 0:  # Demo logic
            at_risk.append(student)
    
    return render_template('risk_students.html', students=at_risk)

@app.route('/admin/grade-distribution')
@roles_required('admin')
def grade_distribution():
    # Get grade distribution data
    grades = db.session.query(
        AssessmentResult.score,
        db.func.count(AssessmentResult.id)
    ).group_by(AssessmentResult.score).all()
    
    return render_template('grade_distribution.html', grades=grades)

@app.route('/admin/attendance-summary')
@roles_required('admin')
def attendance_summary():
    # Get attendance summary data
    attendance_data = db.session.query(
        Attendance.status,
        db.func.count(Attendance.id)
    ).group_by(Attendance.status).all()
    
    # Convert to dictionary format
    summary = {
        'Present': 0,
        'Absent': 0
    }
    
    for status, count in attendance_data:
        summary[status] = count
    
    return render_template('attendance_summary.html', summary=summary)




# Update dashboard_admin route
@app.route('/dashboard/admin')
@roles_required('admin')
def dashboard_admin():
    stats = {
        'total_users': User.query.count(),
        'active_students': User.query.filter_by(role='student', is_active=True).count(),
        'pending_registrations': Registration.query.filter_by(status='Pending').count(),
        'at_risk_students': User.query.filter_by(role='student').count() // 5  # Demo value
    }
    
    recent_activities = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(5).all()
    
    # Demo grade data - replace with actual query
    grade_data = {
        'labels': ['Week 1', 'Week 2', 'Week 3', 'Week 4'],
        'data': [75, 82, 78, 85]
    }
    
    return render_template(
        'dashboard_admin.html',
        stats=stats,
        recent_activities=recent_activities,
        grade_labels=grade_data['labels'],
        grade_data=grade_data['data']
    )    



# --- Registrar: Add Student or Teacher ---
@app.route('/registrar/add-user', methods=['GET','POST'])
@roles_required('registrar')
def add_user():
    if request.method == 'POST':
        username   = request.form['username']
        email      = request.form['email']
        password   = request.form['password']
        role       = request.form['role']        # student or teacher
        department = request.form.get('department')
        section    = request.form.get('section')

        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            role=role,
            is_active=True,
            department=department,
            section=section
        )
        db.session.add(user)
        db.session.commit()
        flash(f'{role.capitalize()} account created!', 'success')
        return redirect(url_for('dashboard_registrar'))
    return render_template('add_user.html')
#---Edit user info-----    
@app.route('/registrar/edit-user/<int:user_id>', methods=['GET','POST'])
@roles_required('registrar')
def edit_user(user_id):
    if prevent_admin_modification(user_id):
        department = request.form.get('department', None)
    u = User.query.get_or_404(user_id)
    if request.method == 'POST':
        department = request.form['department']
        section = request.form['section']
        
        # Validate department and section
        valid_departments = [d[0] for d in db.session.query(User.department).distinct().all()]
        valid_sections = [s[0] for s in db.session.query(User.section).distinct().all()]
        
        if department not in valid_departments:
            flash('Invalid department selected.', 'danger')
            return redirect(url_for('edit_user', user_id=user_id))
        
        if section not in valid_sections:
            flash('Invalid section selected.', 'danger')
            return redirect(url_for('edit_user', user_id=user_id))
        
        u.department = department
        u.section = section
        db.session.commit()
        flash('User reassigned!', 'success')
        return redirect(url_for('dashboard_registrar'))
    return render_template('edit_user.html', u=u)

# Add these routes after the existing registrar routes

# ---------------------------
# Registrar: Full Management
# ---------------------------
@app.route('/registrar/department-section', methods=['GET', 'POST'])
@roles_required('registrar')
def manage_departments_sections():
    if request.method == 'POST':
        # Add/update department-section logic
        action = request.form.get('action')
        if action == 'add_department':
            new_dept = request.form['department']
            # Add to database
            flash(f'Department {new_dept} added', 'success')
        elif action == 'add_section':
            new_section = request.form['section']
            # Add to database
            flash(f'Section {new_section} added', 'success')
        return redirect(url_for('manage_departments_sections'))
    
    # Get existing departments and sections
    departments = db.session.query(User.department).distinct().all()
    sections = db.session.query(User.section).distinct().all()
    return render_template('manage_dept_section.html', 
                         departments=departments, sections=sections)

@app.route('/registrar/bulk-actions', methods=['GET', 'POST'])
@roles_required('registrar')
def bulk_actions():
    if request.method == 'POST':
        file = request.files.get('csv_file')
        if file:
            # Process CSV bulk upload
            df = pd.read_csv(file)
            # Implement bulk user/course operations
            flash('Bulk operation completed', 'success')
            return redirect(url_for('bulk_actions'))
    return render_template('bulk_actions.html')

@app.route('/registrar/registration-status')
@roles_required('registrar')
def registration_status():
    status_filter = request.args.get('status', 'all')
    query = Registration.query
    
    if status_filter != 'all':
        query = query.filter_by(status=status_filter)
    
    registrations = query.order_by(Registration.timestamp.desc()).all()
    return render_template('registration_status.html', 
                         registrations=registrations, 
                         current_filter=status_filter)

@app.route('/registrar/user-management')
@roles_required('registrar')
def registrar_user_management():
    users = User.query.order_by(User.role, User.username).all()
    return render_template('registrar_user_management.html', users=users)




# Update the existing dashboard route
@app.route('/dashboard/registrar')
@roles_required('registrar')
def dashboard_registrar():
    # Get essential statistics
    stats = {
        'total_students': User.query.filter_by(role='student').count(),
        'pending_registrations': Registration.query.filter_by(status='Pending').count(),
        'active_semesters': Semester.query.filter_by(is_open=True).count(),
        'total_courses': Course.query.count()
    }
    
    # Get recent activities
    recent_registrations = Registration.query.order_by(
        Registration.timestamp.desc()
    ).limit(5).all()
    
    return render_template(
        'dashboard_registrar.html',
        stats=stats,
        recent_registrations=recent_registrations
    )



# ---------------------------
# Teacher: Assessment Forms & Simulation
# ---------------------------
@app.route('/assessment-forms/create', methods=['GET','POST'])
@roles_required('teacher')
def create_assessment_form():
    if request.method=='POST':
        form = AssessmentForm(
            teacher_id     = session['user_id'],
            course         = request.form['course'],
            department     = request.form['department'],
            section        = request.form['section'],
            quiz_weight    = float(request.form['quiz_weight']),
            test1_weight   = float(request.form['test1_weight']),
            test2_weight   = float(request.form['test2_weight']),
            mid_weight     = float(request.form['mid_weight']),
            project_weight = float(request.form['project_weight']),
            assign_weight  = float(request.form['assign_weight']),
            final_weight   = float(request.form['final_weight']),
        )
        db.session.add(form)
        db.session.commit()
        flash('Assessment form created!', 'success')
        return redirect(url_for('list_assessment_forms'))
    return render_template('create_assessment_form.html')

@app.route('/assessment-forms')
@roles_required('teacher')
def list_assessment_forms():
    forms = AssessmentForm.query.filter_by(teacher_id=session['user_id']).all()
    return render_template('assessment_forms.html', forms=forms)
#----teacher add and edit assessment------#
@app.route('/assessment-forms/edit/<int:form_id>', methods=['GET', 'POST'])
@roles_required('teacher')
def edit_assessment_form(form_id):
    form = AssessmentForm.query.get_or_404(form_id)
    if form.teacher_id != session['user_id']:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('list_assessment_forms'))
    
    if request.method == 'POST':
        try:
            form.course = request.form['course']
            form.department = request.form['department']
            form.section = request.form['section']
            weights = [
                float(request.form['quiz_weight']),
                float(request.form['test1_weight']),
                float(request.form['test2_weight']),
                float(request.form['mid_weight']),
                float(request.form['project_weight']),
                float(request.form['assign_weight']),
                float(request.form['final_weight'])
            ]
            total = sum(weights)
            
            if total != 100:
                flash('Total weights must equal 100%', 'danger')
                return redirect(url_for('edit_assessment_form', form_id=form_id))
            
            form.quiz_weight = weights[0]
            form.test1_weight = weights[1]
            form.test2_weight = weights[2]
            form.mid_weight = weights[3]
            form.project_weight = weights[4]
            form.assign_weight = weights[5]
            form.final_weight = weights[6]
            
            db.session.commit()
            flash('Assessment form updated successfully', 'success')
            return redirect(url_for('list_assessment_forms'))
        except Exception as e:
            flash(f'Error updating form: {str(e)}', 'danger')
    
    return render_template('edit_assessment_form.html', form=form)

@app.route('/assessment-forms/delete/<int:form_id>', methods=['POST'])
@roles_required('teacher')
def delete_assessment_form(form_id):
    form = AssessmentForm.query.get_or_404(form_id)
    if form.teacher_id != session['user_id']:
        flash('Unauthorized action', 'danger')
        return redirect(url_for('list_assessment_forms'))
    
    db.session.delete(form)
    db.session.commit()
    flash('Assessment form deleted successfully', 'success')
    return redirect(url_for('list_assessment_forms'))


@app.route('/simulate-performance', methods=['GET','POST'])
@roles_required('teacher')
def simulate_performance():
    if request.method=='POST':
        g1 = float(request.form.get('G1',0))
        g2 = float(request.form.get('G2',0))
        data={ 'G1':g1,'G2':g2,'failures':0,'absences':0,'higher':'no','studytime':0,'age':0,'Dalc':0,'goout':0 }
        predictor_model = get_predictor_model()
        df_sim = pd.DataFrame([encode_inputs(data)])
        predicted = predictor_model.predict(df_sim)[0]
        return render_template('simulate_results.html', predicted=round(predicted,2))
    return render_template('simulate_form.html')
#        _______________________       # 
#--------\                     /-------#
#  ----   \_upload-attendance_/   ---- #  
# *****   \__________________/******** #
#  
@app.route('/upload-attendance', methods=['GET', 'POST'])
@roles_required('teacher')
def upload_attendance():
    teacher_username = session.get('username')
    courses = Course.query.filter_by(instructor=teacher_username).all()
    
    if request.method == 'POST':
        course_id = request.form.get('course_id')
        file = request.files.get('file')
        
        if not course_id or not file:
            flash('Missing required fields', 'danger')
            return redirect(url_for('upload_attendance'))
        
        try:
            df = pd.read_csv(file)
            required_columns = ['username', 'date', 'status']
            if not all(col in df.columns for col in required_columns):
                flash('CSV file must contain username, date, and status columns', 'danger')
                return redirect(url_for('upload_attendance'))
            
            success = 0
            errors = []
            
            for index, row in df.iterrows():
                student = User.query.filter_by(username=row['username'], role='student').first()
                if not student:
                    errors.append(f"Row {index+1}: Student not found")
                    continue
                
                try:
                    date = datetime.strptime(row['date'], '%Y-%m-%d').date()
                except ValueError:
                    errors.append(f"Row {index+1}: Invalid date format")
                    continue
                
                if row['status'] not in ['Present', 'Absent']:
                    errors.append(f"Row {index+1}: Invalid status")
                    continue
                
                existing = Attendance.query.filter_by(
                    student_id=student.id,
                    course_id=course_id,
                    date=date
                ).first()
                
                if existing:
                    errors.append(f"Row {index+1}: Attendance already exists")
                    continue
                
                attendance = Attendance(
                    student_id=student.id,
                    course_id=course_id,
                    date=date,
                    status=row['status']
                )
                db.session.add(attendance)
                success += 1
            
            db.session.commit()
            flash(f"Successfully uploaded {success} records. {len(errors)} errors", 'success')
            if errors:
                flash("Errors: " + ", ".join(errors[:5]), 'warning')
            
        except Exception as e:
            flash(f"Error processing file: {str(e)}", 'danger')
        
        return redirect(url_for('upload_attendance'))
    
    return render_template('upload_attendance.html', courses=courses)


#---grade upload-----#
@app.route('/upload-grades', methods=['GET', 'POST'])
@roles_required('teacher')
def upload_grades():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file uploaded', 'danger')
            return redirect(url_for('upload_grades'))
        
        file = request.files['file']
        if not file.filename.endswith('.csv'):
            flash('Only CSV files allowed', 'danger')
            return redirect(url_for('upload_grades'))
        
        try:
            df = pd.read_csv(file)
            required_columns = ['username', 'G1', 'G2', 'failures', 'absences', 'studytime', 'age', 'Dalc', 'goout', 'higher']
            if not all(col in df.columns for col in required_columns):
                flash('Missing required columns in CSV', 'danger')
                return redirect(url_for('upload_grades'))
            
            predictor = get_predictor_model()
            classifier = get_classifier_model()
            results = []
            
            for _, row in df.iterrows():
                student = User.query.filter_by(username=row['username'], role='student').first()
                if not student:
                    continue
                
                data = row.to_dict()
                encoded = encode_inputs(data)
                df_input = pd.DataFrame([encoded])
                
                try:
                    g3 = predictor.predict(df_input)[0]
                    risk = classifier.predict(df_input)[0]
                    recommendation = generate_recommendation(df_input.iloc[0])
                except Exception as e:
                    continue
                
                results.append({
                    'username': row['username'],
                    'g3': round(g3, 2),
                    'risk': 'At Risk' if risk == 1 else 'Not At Risk',
                    'recommendation': recommendation
                })
            
            return render_template('grade_upload_results.html', results=results)
        
        except Exception as e:
            flash(f'Error processing file: {str(e)}', 'danger')
            return redirect(url_for('upload_grades'))
    
    return render_template('upload_grades.html')
#---------------------------------------   
#---- view teaching assnmg---
#------------------------------------
@app.route('/teaching-assignments')
@roles_required('teacher')
def teaching_assignments():
    teacher_username = session.get('username')
    
    # Get assigned courses
    courses = Course.query.filter_by(instructor=teacher_username).all()
    
    # Get students in each course section
    course_data = []
    for course in courses:
        # Get students in this course's department and section
        students = User.query.filter_by(
            role='student',
            department=course.department,
            section=course.section
        ).all()
        
        # Get number of students
        student_count = len(students)
        
        course_data.append({
            'course': course,
            'students': students,
            'student_count': student_count
        })
    
    return render_template('teaching_assignments.html', 
                         course_data=course_data,
                         teacher=teacher_username)

# ---------------------------
# Prediction Routes
# ---------------------------
@app.route('/')
def index():
    if session.get('role'):
        return redirect(url_for(f'dashboard_{session.get("role")}'))
    return redirect(url_for('login'))

@app.route('/predict', methods=['POST'])
@roles_required('student')
def predict():

    data={feat:request.form.get(feat) for feat in input_features}
    for num in ['G1','G2','failures','absences','studytime','age','Dalc','goout']:
        data[num]=float(data.get(num) or 0)
    df_input=pd.DataFrame([encode_inputs(data)])
    g3 = get_predictor_model().predict(df_input)[0]
    risk = get_classifier_model().predict(df_input)[0]
    rec = generate_recommendation(df_input.iloc[0])
        # store for PDF export
    session['predicted_grade'] =float(g3)
    session['risk_status']     =int(risk)
    session['recommendation']  = rec

    return render_template('result.html', predicted_grade=round(g3,2), risk_status=('At Risk' if risk==1 else 'Not At Risk'), recommendation=rec)

from io import BytesIO
from flask import make_response
from reportlab.pdfgen import canvas


# Error Handling Pages
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

# ---------------------------
# PDF Export Route
# ---------------------------

# Updated PDF Export Route with proper response handling
@app.route('/export-pdf')
@roles_required('student')
def export_pdf():
    # Get prediction data from session
    pred = session.get('predicted_grade')
    risk = session.get('risk_status')
    rec = session.get('recommendation')
    
    if None in [pred, risk, rec]:
        flash('No prediction found. Please make a prediction first.', 'warning')
        return redirect(url_for('predict_form'))

    buffer = BytesIO()
    p = canvas.Canvas(buffer)
    p.setFont('Helvetica', 12)
    p.drawString(100, 800, f"Predicted Final Grade (G3): {pred}")
    p.drawString(100, 780, f"Risk Status: {'At Risk' if risk == 1 else 'Not At Risk'}")
    p.drawString(100, 760, "Recommendation:")
    text = p.beginText(100, 740)
    for line in rec.split('\n'):
        text.textLine(line)
    p.drawText(text)
    p.showPage()
    p.save()
    
    buffer.seek(0)
    response = make_response(buffer.getvalue())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'attachment; filename=prediction_report.pdf'
    return response


#-- student_view their attendance --#
@app.route('/attendance', methods=['GET', 'POST'])
@roles_required('student')
def view_attendance():
    student_id = session['user_id']
    
    # Get all courses the student is enrolled in
    courses = Course.query.join(Enrollment).filter(
        Enrollment.student_id == student_id
    ).distinct().all()
    
    context = {
        'courses': courses,
        'records': [],
        'selected_course': None,
        'chart_data': None
    }
    
    # In view_attendance route
    if request.method == 'POST':
        course_id = request.form.get('course_id')
        if not course_id:
            flash('Please select a valid course.', 'warning')
            return redirect(url_for('view_attendance'))
        
        selected_course = Course.query.get(course_id)
        if not selected_course:
            flash('Selected course does not exist.', 'danger')
            return redirect(url_for('view_attendance'))
        
        # Get records FOR THE SELECTED COURSE
        records = Attendance.query.filter_by(
            student_id=student_id,
            course_id=course_id
        ).order_by(Attendance.date.desc()).all()
        
        total = len(records)
        present = len([r for r in records if r.status == 'Present'])
        # Ensure present does not exceed total
        present = min(present, total)
        absent = total - present if total > 0 else 0
        
        # Calculate attendance stats
        chart_data = {
            'labels': ['Present', 'Absent'],
            'data': [present, absent],
            'colors': ['#4e73df', '#e74a3b'],
            'total': total,
            'percentage': round((present / total) * 100, 2) if total > 0 else 0  # Ensure no division by zero
        }
        
        context.update({
            'records': records,
            'selected_course': selected_course,
            'chart_data': chart_data
        })
    else:
        # Default GET request
        records = Attendance.query.filter_by(student_id=student_id)\
            .order_by(Attendance.date.desc()).all()
        context.update({
            'records': records,
            'selected_course': None,
            'chart_data': None
        })
    
    return render_template('attendance.html', **context)

 #--- My assessment-----   

@app.route('/my-assessments')
@roles_required('student')
def my_assessments():
    me = User.query.get(session['user_id'])
    # find all forms for this student’s dept & section with pagination
    page = request.args.get('page', 1, type=int)
    forms = AssessmentForm.query.filter_by(
        department=me.department,
        section=me.section
    ).paginate(page=page, per_page=10)  # 10 forms per page
    return render_template('my_assessments.html', forms=forms.items, pagination=forms, me=me)


if __name__=='__main__':
    app.run(debug=True)
