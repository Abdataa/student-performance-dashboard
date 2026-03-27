from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user
from app import db
from app.core.models import User, AuditLog, SystemConfig, APIToken, Registration
from app.admin.utils import admin_required
from app.admin.forms import AdminUserForm

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

# Admin Dashboard Route

@admin_bp.route('/dashboard/admin')
@login_required
@admin_required
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

        # System health data
    try:
        db.session.execute('SELECT 1')
        db_status = 'OK'
    except Exception as e:
        db_status = f'ERROR: {str(e)}'
    
    try:
        predictor = get_predictor_model()
        classifier = get_classifier_model()
        ml_status = 'Loaded'
    except Exception as e:
        ml_status = f'ERROR: {str(e)}'
    
    try:
        from pathlib import Path
        db_path = app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
        db_size = Path(db_path).stat().st_size / (1024*1024)  # MB
        db_size = f"{db_size:.2f} MB"
    except Exception as e:
        db_size = f"Error: {str(e)}"
    
    # System metrics
    system_info = {
        'cpu_usage': f"{psutil.cpu_percent()}%",
        'memory_usage': f"{psutil.virtual_memory().percent}%",
        'disk_usage': f"{psutil.disk_usage('/').percent}%",
    }
    
    # Service status
    services = {
        'database': {'status': db_status},
        'ml_models': {'status': ml_status}
    }
    
    return render_template(
        'dashboard_admin.html',
        stats=stats,
        recent_activities=recent_activities,
        grade_labels=grade_data['labels'],
        grade_data=grade_data['data'],
        db_size=db_size,
        services=services,
        system_info=system_info
    )
    




@admin_bp.route('/user-management')
@login_required
@admin_required
def user_management():
    page = request.args.get('page', 1, type=int)
    per_page = 10  # Number of users per page
    users = User.query.paginate(page=page, per_page=per_page)
    return render_template('user_management.html', users=users.items, pagination=users)



# Audit Logs Route
@admin_bp.route('/admin/audit-logs')
@login_required
@admin_required
def audit_logs():
    page = request.args.get('page', 1, type=int)
    pagination = AuditLog.query.order_by(AuditLog.timestamp.desc()).paginate(page=page, per_page=20)
    return render_template('audit_logs.html', pagination=pagination)
# System Backup Route
@admin_bp.route('/admin/system-backup', methods=['GET', 'POST'])
@login_required
@admin_required
def system_backup():
    if request.method == 'POST':
        # Add actual backup implementation
        flash('Backup created successfully', 'success')
        return redirect(url_for('system_backup'))
    return render_template('system_backup.html')

# Email Templates Route
@admin_bp.route('/admin/email-templates', methods=['GET', 'POST'])
@login_required
@admin_required
def email_templates():
    if request.method == 'POST':
        # Add email template saving logic
        flash('Email templates updated', 'success')
        return redirect(url_for('email_templates'))
    return render_template('email_templates.html')

@admin_bp.route('/registrations/semester/<int:reg_id>/reject', methods=['POST'])
@login_required
@admin_required
def reject_semester(reg_id):
    r = Registration.query.get_or_404(reg_id)
    db.session.delete(r)
    db.session.commit()
    flash('Registration rejected', 'info')
    return redirect(url_for('semester_registrations'))

#---------
# Enrollment Assignment
# ---------------------------
@admin_bp.route('/admin/enroll', methods=['GET','POST'])
@login_required
@admin_required
def enroll_students():
    if request.method=='POST':
        student_id = request.form['student_id']
        course_id  = request.form['course_id']
        sem_id     = request.form['semester_id']
        e = Enrollment(student_id=student_id, course_id=course_id, semester_id=sem_id)
        db.session.add(e)
        db.session.commit()
        flash('Student enrolled','success')
        return redirect(url_for('enroll_students'))
    students = User.query.filter_by(role='student', is_active=True).all()
    courses  = Course.query.all()
    semesters= Semester.query.all()
    return render_template('enroll_students.html',
                            students=students, courses=courses, semesters=semesters)

@admin_bp.route('/admin-stats')
@login_required
@admin_required
def admin_stats():
    total_users = User.query.count()
    role_counts = dict(db.session.query(User.role, db.func.count(User.id)).group_by(User.role).all())
    risk_data   = {'at_risk': 34, 'not_at_risk': 66}
    return render_template('admin_stats.html', total_users=total_users, role_counts=role_counts, risk_data=risk_data)

@admin_bp.route('/registrations')
@login_required
@admin_required
def registrations():
    page = request.args.get('page', 1, type=int)
    pending = User.query.filter_by(role='student', is_active=False).paginate(page=page, per_page=10)  # 10 users per page
    return render_template('registrations.html', pending=pending.items, pagination=pending)

@admin_bp.route('/approve/<int:user_id>', methods=['POST'])
@login_required
@admin_required
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


@admin_bp.route('/reject/<int:user_id>', methods=['GET', 'POST'])
@login_required
@admin_required
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
@admin_bp.route('/admin/add-registrar', methods=['GET','POST'])
@login_required
@admin_required
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
        return redirect(url_for('user_management'))
    return render_template('add_registrar.html')


@admin_bp.route('/admin/add-user', methods=['GET','POST'])
@login_required  
@admin_required    
def admin_add_user():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form.get('password')  # Moved inside POST block
        role = request.form.get('role')  
        department = request.form.get('department')
        section = request.form.get('section')

        # Check for duplicates
        if User.query.filter_by(username=username).first():
            flash('Username already exists!', 'danger')
            return render_template('admin_add_user.html', form_data=request.form)
            
        if User.query.filter_by(email=email).first():
            flash('Email already registered!', 'danger')
            return render_template('admin_add_user.html', form_data=request.form)
        
        # Validate required fields
        if not all([username, email, password]):
            flash('All fields are required', 'danger')
            return render_template('admin_add_user.html', form_data=request.form)

        # Create user
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
        flash('User created successfully!', 'success')
        return redirect(url_for('user_management'))
    
    # Handle GET request
    return render_template('admin_add_user.html')

@admin_bp.route('/admin/edit-user/<int:user_id>', methods=['GET','POST'])
@login_required
@admin_required
def admin_edit_user(user_id):
    u = User.query.get_or_404(user_id)
    if request.method=='POST':
        u.username   = request.form['username']
        u.email      = request.form['email']
        u.role       = request.form['role']
        u.department = request.form.get('department')
        u.section    = request.form.get('section')
        u.password_hash = generate_password_hash(request.form['password'])
        db.session.commit()
        flash('User updated!', 'success')
        return redirect(url_for('user_management'))
    return render_template('admin_edit_user.html', u=u)

@admin_bp.route('/admin/delete-user/<int:user_id>', methods=['POST'])
@login_required
@admin_required

def admin_delete_user(user_id):
    u = User.query.get_or_404(user_id)
    db.session.delete(u)
    db.session.commit()
    flash('User deleted.', 'info')
    return redirect(url_for('user_management'))
##############

@admin_bp.route('/manage-semesters')
@login_required
@admin_required
def manage_semesters():
    semesters = Semester.query.order_by(Semester.name.desc()).all()
    return render_template('manage_semesters.html', semesters=semesters)

@admin_bp.route('/semesters/toggle/<int:sem_id>', methods=['POST'])
@login_required
@admin_required
def toggle_semester(sem_id):
    sem = Semester.query.get_or_404(sem_id)
    sem.is_open = not sem.is_open
    db.session.commit()
    flash(f"{sem.name} is now {'open' if sem.is_open else 'closed'}", "info")
    return redirect(url_for('manage_semesters'))

@admin_bp.route('/semesters/add', methods=['GET', 'POST'])
@login_required
@admin_required
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
                    instructor=User.query.get(int(request.form[f'course_{i}_instructor'])),  # Assign User object
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
@admin_bp.route('/semesters/close/<int:sem_id>', methods=['POST'])
@login_required
@admin_required
def close_semester(sem_id):
    sem = Semester.query.get_or_404(sem_id)
    sem.is_open = False  # This only prevents new registrations
    db.session.commit()
    flash(f"{sem.name} has been closed", "info")
    return redirect(url_for('manage_semesters'))
# ---------------------------
# API Token Management

@admin_bp.route('/admin/api-tokens', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_api_tokens():
    if request.method == 'POST':
        # Create new token
        description = request.form.get('description', '').strip()
        permissions = request.form.getlist('permissions')
        expiry_days = int(request.form.get('expiry_days', 90))
        
        new_token = APIToken(
            description=description,
            permissions=permissions,
            expires_at=datetime.utcnow() + timedelta(days=expiry_days)
        )
        new_token.generate_token()
        
        db.session.add(new_token)
        db.session.commit()
        
        flash('API token created successfully!', 'success')
        return redirect(url_for('manage_api_tokens'))
    
    tokens = APIToken.query.order_by(APIToken.created_at.desc()).all()
    return render_template('api_tokens.html', tokens=tokens)
# ---------------------------
@admin_bp.route('/admin/api-tokens/revoke/<int:token_id>', methods=['POST'])
@login_required
@admin_required
def revoke_api_token(token_id):
    token = APIToken.query.get_or_404(token_id)
    token.is_active = False
    db.session.commit()
    flash('API token revoked', 'info')
    return redirect(url_for('manage_api_tokens'))
# ---------------------------
# Renew API Token
@admin_bp.route('/admin/api-tokens/renew/<int:token_id>', methods=['POST'])
@login_required
@admin_required
def renew_api_token(token_id):
    token = APIToken.query.get_or_404(token_id)
    token.generate_token()
    token.expires_at = datetime.utcnow() + timedelta(days=90)
    token.is_active = True
    db.session.commit()
    flash('API token renewed', 'success')
    return redirect(url_for('manage_api_tokens'))
# --------------------------- 
# Delete API Token

@admin_bp.route('/admin/api-tokens/delete/<int:token_id>', methods=['POST'])
@login_required
@admin_required
def delete_api_token(token_id):
    token = APIToken.query.get_or_404(token_id)
    db.session.delete(token)
    db.session.commit()
    flash('API token deleted', 'info')
    return redirect(url_for('manage_api_tokens'))

# ---------------------------
# System Health Check
# ---------------------------
@admin_bp.route('/admin/system-health')
@login_required
@admin_required
@login_required  # Extra security layer
def system_health():
    # ----------------------
    # Database Health Check
    # ----------------------
    try:
        db.session.execute(text('SELECT 1'))  # ✅ Use text() for raw SQL
        db_status = {'status': 'OK', 'class': 'success'}
    except Exception as e:
        db_status = {'status': f'ERROR: {str(e)}', 'class': 'danger'}
    
    # ----------------------
    # ML Model Status
    # ----------------------
    try:
        predictor = get_predictor_model()
        classifier = get_classifier_model()
        ml_status = {'status': 'Loaded', 'class': 'success'}
    except Exception as e:
        ml_status = {'status': f'ERROR: {str(e)}', 'class': 'danger'}
    
    # ----------------------
    # Database Storage Size
    # ----------------------
    try:
        db_uri = app.config['SQLALCHEMY_DATABASE_URI']
        if db_uri.startswith('sqlite:///'):
            db_path = os.path.abspath(db_uri.replace('sqlite:///', ''))
            db_size_val = Path(db_path).stat().st_size / (1024 * 1024)  # MB
            db_size = f"{db_size_val:.2f} MB"
        else:
            db_size = "Unavailable (non-sqlite DB)"
    except Exception as e:
        db_size = f"Error: {str(e)}"
    
    # ----------------------
    # System Metrics
    # ----------------------
    try:
        system_info = {
            'platform': platform.system(),
            'release': platform.release(),
            'python_version': platform.python_version(),
            'cpu_usage': f"{psutil.cpu_percent()}%",
            'memory_usage': f"{psutil.virtual_memory().percent}%",
            'disk_usage': f"{psutil.disk_usage('/').percent}%",
            'uptime': str(timedelta(seconds=int(time.time() - psutil.boot_time())))
        }
    except Exception as e:
        system_info = {
            'platform': 'Error',
            'release': 'Error',
            'python_version': 'Error',
            'cpu_usage': f"Error: {str(e)}",
            'memory_usage': 'Error',
            'disk_usage': 'Error',
            'uptime': 'Error'
        }

    # ----------------------
    # Service Status Summary
    # ----------------------
    services = {
        'database': db_status,
        'ml_models': ml_status,
        'scheduler': {
            'status': 'Running' if scheduler.running else 'Stopped',
            'class': 'success' if scheduler.running else 'danger'
        },
        'jobs': f"{len(scheduler.get_jobs())} active"
    }
    
    # ----------------------
    # Render System Health Template
    # ----------------------
    return render_template(
        'system_health.html',
        db_size=db_size,
        services=services,
        system_info=system_info,
        scheduler=scheduler,
        current_time=datetime.utcnow()
    )

# ---------------------------
# --- Admin: Manage Courses ---

@admin_bp.route('/manage-courses')
@login_required
@admin_required
def manage_courses():
    courses = Course.query.order_by(Course.department, Course.section, Course.name).all()
    return render_template('manage_courses.html', courses=courses)

@admin_bp.route('/manage-courses/add', methods=['GET','POST'])
@login_required
@admin_required
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

####            ----------------------------
# Edit Course
# ----------------------------
@admin_bp.route('/manage-courses/edit/<int:course_id>', methods=['GET','POST'])
@login_required
@admin_required
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

# ----------------------------
# Delete Course
@admin_bp.route('/manage-courses/delete/<int:course_id>', methods=['POST'])
@login_required
@admin_required
def delete_course(course_id):
    c = Course.query.get_or_404(course_id)
    db.session.delete(c)
    db.session.commit()
    flash('Course deleted.', 'info')
    return redirect(url_for('manage_courses'))

@admin_bp.route('/admin/system-settings', methods=['GET', 'POST'])
@login_required
@admin_required
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
#--------------------------------------------------
# Update your security_settings route
@admin_bp.route('/admin/security-settings', methods=['GET','POST'])
@login_required
@admin_required
def security_settings():
    if request.method == 'POST':
        set_config('login_attempts', int(request.form['max_login_attempts']))
        set_config('password_expiry', int(request.form['password_expiry_days']))
        set_config('session_timeout', 'session_timeout' in request.form)
        set_config('session_timeout_minutes', int(request.form.get('session_timeout_minutes', 30)))
        flash('Security settings updated', 'success')
    
    return render_template('security_settings.html', 
                          config={
                              'max_login_attempts': get_config('login_attempts', 5),
                              'password_expiry': get_config('password_expiry', 90),
                              'session_timeout': get_config('session_timeout', False),
                              'session_timeout_minutes': get_config('session_timeout_minutes', 30)
                          },
                          current_time=datetime.utcnow())
#----admin------data integrity checks-------
@admin_bp.route('/admin/data-integrity')
@login_required
@admin_required
def data_integrity():
    issues = []
    
    # 1. Orphaned enrollments (student doesn't exist)
    orphaned_enrollments = Enrollment.query.filter(
        ~Enrollment.student_id.in_(db.session.query(User.id))
    ).all()
    
    if orphaned_enrollments:
        issues.append({
            'type': 'Orphaned Enrollments',
            'count': len(orphaned_enrollments),
            'details': orphaned_enrollments
        })
    
    # 2. Course without instructor
    courses_without_instructor = Course.query.filter(
        Course.instructor_rel == None
    ).all()
    
    if courses_without_instructor:
        issues.append({
            'type': 'Courses Without Instructor',
            'count': len(courses_without_instructor),
            'details': courses_without_instructor
        })
    
    # 3. Grade anomalies
    anomaly_grades = AssessmentResult.query.filter(
        AssessmentResult.score > 100
    ).all()
    
    # 4. Invalid assessment weights
    invalid_weights = AssessmentForm.query.filter(
        (AssessmentForm.quiz_weight + 
         AssessmentForm.test1_weight +
         AssessmentForm.test2_weight +
         AssessmentForm.mid_weight +
         AssessmentForm.project_weight +
         AssessmentForm.assign_weight +
         AssessmentForm.final_weight) != 100
    ).all()
    
    if invalid_weights:
        issues.append({
            'type': 'Invalid Assessment Weights',
            'count': len(invalid_weights),
            'details': invalid_weights
        })
    
    # 5. Users without role
    users_without_role = User.query.filter(
        User.role == None
    ).all()
    
    if users_without_role:
        issues.append({
            'type': 'Users Without Role',
            'count': len(users_without_role),
            'details': users_without_role
        })
    
    return render_template('data_integrity.html', 
                          issues=issues, 
                          anomalies=anomaly_grades,
                          current_time=datetime.utcnow())
# ---------------------------
# Admin Analytics Routes
# ---------------------------
@admin_bp.route('/admin/risk-students')
@login_required
@admin_required
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

@admin_bp.route('/admin/grade-distribution')
@login_required
@admin_required

def grade_distribution():
    # Get grade distribution data
    grades = db.session.query(
        AssessmentResult.score,
        db.func.count(AssessmentResult.id)
    ).group_by(AssessmentResult.score).all()
    
    return render_template('grade_distribution.html', grades=grades)

@admin_bp.route('/admin/attendance-summary')
@login_required
@admin_required

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


@admin_bp.route('/semesters/close/<int:sem_id>', methods=['POST'])
@login_required
@admin_required
def close_semester(sem_id):
    sem = Semester.query.get_or_404(sem_id)
    sem.is_open = False  # This only prevents new registrations
    db.session.commit()
    flash(f"{sem.name} has been closed", "info")
    return redirect(url_for('manage_semesters'))

#fix orphaned enrollments
@admin_bp.route('/admin/fix-orphaned/<int:enrollment_id>', methods=['POST'])
@login_required
@admin_required
def fix_orphaned(enrollment_id):
    enrollment = Enrollment.query.get_or_404(enrollment_id)
    db.session.delete(enrollment)
    db.session.commit()
    flash('Orphaned enrollment removed', 'success')
    return redirect(url_for('data_integrity'))  





