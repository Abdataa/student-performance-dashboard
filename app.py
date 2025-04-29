from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import joblib
import pandas as pd
from datetime import datetime
from ML.study_recommendation import generate_recommendation

app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///student_performance.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False



db = SQLAlchemy(app)

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

class Attendance(db.Model):
    __tablename__ = 'attendance'
    id         = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    date       = db.Column(db.Date, nullable=False)
    status     = db.Column(db.String(10), nullable=False)  # e.g. 'Present' or 'Absent'

    student    = db.relationship('User', backref='attendance_records')
class User(db.Model):
    __tablename__ = 'users'
    id            = db.Column(db.Integer,    primary_key=True)
    username      = db.Column(db.String(80), unique=True, nullable=False)
    email         = db.Column(db.String(120),unique=True, nullable=False)
    password_hash = db.Column(db.String(128),nullable=False)
    role          = db.Column(db.String(20), nullable=False)
    is_active     = db.Column(db.Boolean,    default=False)
    # new fields:
    department    = db.Column(db.String(100), nullable=True)
    section       = db.Column(db.String(50),  nullable=True)

   

# Create all tables
with app.app_context():
    db.create_all()

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
def encode_inputs(data):
    data['higher'] = 1 if data.get('higher') == 'yes' else 0
    return data


# Role-based decorator
def role_required(role):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if session.get('role') != role:
                flash('Access denied.', 'danger')
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
# Authentication Routes
# ---------------------------
# this view has been left for later improvement 

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email    = request.form['email']
        password = request.form['password']
        user     = User.query.filter_by(email=email).first()

        # 1) Check credentials
        if not user or not check_password_hash(user.password_hash, password):
            flash('Invalid credentials.', 'danger')
            return redirect(url_for('login'))

        # 2) Check activation
        if not user.is_active:
            flash('Your account is pending approval. Please wait.', 'warning')
            return redirect(url_for('login'))

        # 3) Log in
        session['user_id']  = user.id
        session['role']     = user.role
        session['username'] = user.username
        flash('Login successful!', 'success')
        return redirect(url_for(f'dashboard_{user.role}'))

    return render_template('login.html')



@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out.', 'info')
    return redirect(url_for('login'))

# ---------------------------
# Dashboard Routes
# ---------------------------
@app.route('/dashboard/student')
@role_required('student')
def dashboard_student():
    return render_template('dashboard_student.html', name=session.get('username'))

@app.route('/dashboard/teacher')
@role_required('teacher')
def dashboard_teacher():
    return render_template('dashboard_teacher.html', name=session.get('username'))

@app.route('/dashboard/registrar')
@role_required('registrar')
def dashboard_registrar():
    page = request.args.get('page', 1, type=int)
    users = User.query.paginate(page=page, per_page=10)  # 10 users per page
    return render_template(
        'dashboard_registrar.html',
        name=session.get('username'),
        users=users.items,
        pagination=users
    )

@app.route('/registrar/toggle-user/<int:user_id>', methods=['POST'])
@role_required('registrar')
def toggle_user(user_id):
    user = User.query.get_or_404(user_id)
    user.is_active = not user.is_active
    db.session.commit()
    flash(f"{user.username} is now {'Active' if user.is_active else 'Inactive'}.", 'info')
    return redirect(url_for('dashboard_registrar'))


@app.route('/dashboard/admin')
@role_required('admin')
def dashboard_admin():
    return render_template('dashboard_admin.html', name=session.get('username'))
@app.route('/profile')
@login_required # any logged-in user
def profile():
    user = User.query.get(session['user_id'])
    return render_template('profile.html', user=user)    
# Student Prediction Input Form
@app.route('/predict-form')
@role_required('student')
def predict_form():
    return render_template('predict_form.html')

# ---------------------------
# Admin Routes
# ---------------------------
@app.route('/admin-stats')
@role_required('admin')
def admin_stats():
    total_users = User.query.count()
    role_counts = dict(db.session.query(User.role, db.func.count(User.id)).group_by(User.role).all())
    risk_data   = {'at_risk': 34, 'not_at_risk': 66}
    return render_template('admin_stats.html', total_users=total_users, role_counts=role_counts, risk_data=risk_data)

@app.route('/user-management')
@role_required('admin')
def user_management():
    page = request.args.get('page', 1, type=int)
    per_page = 10  # Number of users per page
    users = User.query.paginate(page=page, per_page=per_page)
    return render_template('user_management.html', users=users.items, pagination=users)
@app.route('/registrations')
@role_required('admin')
def registrations():
    page = request.args.get('page', 1, type=int)
    pending = User.query.filter_by(role='student', is_active=False).paginate(page=page, per_page=10)  # 10 users per page
    return render_template('registrations.html', pending=pending.items, pagination=pending)
    pending = User.query.filter_by(role='student', is_active=False).all()
    return render_template('registrations.html', pending=pending)
@app.route('/approve/<int:user_id>', methods=['POST'])
@role_required('admin')
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
@role_required('admin')
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
@role_required('admin')
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

# --- Registrar: Add Student or Teacher ---
@app.route('/registrar/add-user', methods=['GET','POST'])
@role_required('registrar')
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
@role_required('registrar')
def edit_user(user_id):
    u = User.query.get_or_404(user_id)
    if request.method == 'POST':
        u.department = request.form['department']
        u.section    = request.form['section']
        db.session.commit()
        flash('User reassigned!', 'success')
        return redirect(url_for('dashboard_registrar'))
    return render_template('edit_user.html', u=u)




# ---------------------------
# Teacher: Assessment Forms & Simulation
# ---------------------------
@app.route('/assessment-forms/create', methods=['GET','POST'])
@role_required('teacher')
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
@role_required('teacher')
def list_assessment_forms():
    forms = AssessmentForm.query.filter_by(teacher_id=session['user_id']).all()
    return render_template('assessment_forms.html', forms=forms)

@app.route('/simulate-performance', methods=['GET','POST'])
@role_required('teacher')
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
#        _______________________     # 
#--------\                     /-------#
#  ----   \_upload-attendance_/   ----   #  
# *****   \__________________/********#
#  
@app.route('/upload-attendance', methods=['GET', 'POST'])
@role_required('teacher')
def upload_attendance():
    if request.method == 'POST':
        file = request.files.get('file')
        if not file:
            flash('No file uploaded', 'danger')
            return redirect(url_for('dashboard_teacher'))
        try:
            df = pd.read_csv(file)  
            # Expect columns: 'username','date','status'
            for _, row in df.iterrows():
                user = User.query.filter_by(username=row['username']).first()
                if not user:
                    continue  # skip unknown usernames
                att = Attendance(
                    student_id=user.id,
                    date=pd.to_datetime(row['date']).date(),
                    status=row['status']
                )
                db.session.add(att)
            db.session.commit()
            flash('Attendance uploaded successfully.', 'success')
            return redirect(url_for('dashboard_teacher'))
        except Exception as e:
            flash(f'Error processing file: {e}', 'danger')
            return redirect(url_for('dashboard_teacher'))
    return render_template('upload_attendance.html')
#---grade upload-----#
@app.route('/upload-grades', methods=['GET', 'POST'])
@role_required('teacher')
def upload_grades():
    if request.method == 'POST':
        predicted = get_predictor_model().predict(df_sim)[0]
        if not file:
            flash('No file uploaded', 'danger')
            return redirect(url_for('upload_grades'))
        try:
            df = pd.read_csv(file)
            results = []
            for _, row in df.iterrows():
                data = row.to_dict()
                for feat in input_features:
                    data.setdefault(feat, 0)
                data = encode_inputs(data)
                inp = pd.DataFrame([data])
                g3   = predictor_model.predict(inp)[0]
                risk = classifier_model.predict(inp)[0]
                rec  = generate_recommendation(inp.iloc[0])
                results.append({
                  'username': data.get('username',''),
                  'g3': round(g3,2),
                  'risk': 'At Risk' if risk==1 else 'Not At Risk',
                  'recommendation': rec
                })
            return render_template('grade_upload_results.html', results=results)
        except Exception as e:
            flash(f'Error processing file: {e}', 'danger')
            return redirect(url_for('upload_grades'))
    return render_template('upload_grades.html')
   


# ---------------------------
# Prediction Routes
# ---------------------------
@app.route('/')
def index():
    if session.get('role'):
        return redirect(url_for(f'dashboard_{session.get("role")}'))
    return redirect(url_for('login'))

@app.route('/predict', methods=['POST'])
@role_required('student')
def predict():
    data={feat:request.form.get(feat) for feat in input_features}
    for num in ['G1','G2','failures','absences','studytime','age','Dalc','goout']:
        data[num]=float(data.get(num) or 0)
    df_input=pd.DataFrame([encode_inputs(data)])
    g3 = predictor_model.predict(df_input)[0]
    risk = classifier_model.predict(df_input)[0]
    rec = generate_recommendation(df_input.iloc[0])
        # store for PDF export
    session['predicted_grade'] =float(g3)
    session['risk_status']     =int (risk)
    session['recommendation']  = rec

    return render_template('result.html', predicted_grade=round(g3,2), risk_status=('At Risk' if risk==1 else 'Not At Risk'), recommendation=rec)

from io import BytesIO
from flask import make_response
from reportlab.pdfgen import canvas

# ---------------------------
# PDF Export Route
# ---------------------------
@app.route('/export-pdf')
@role_required('student')
def export_pdf():
    pred = session.get('predicted_grade')
    risk = session.get('risk_status')
    rec  = session.get('recommendation')

    if pred is None or risk is None:
        flash('No prediction found. Please run a prediction first.', 'warning')
        return redirect(url_for('predict_form'))

    buffer = BytesIO()
    p = canvas.Canvas(buffer)
    p.setFont('Helvetica', 12)
    p.drawString(100, 800, f"Predicted Final Grade (G3): {pred}")
    p.drawString(100, 780, f"Risk Status: {risk}")
    p.drawString(100, 760, "Recommendation:")
    text = p.beginText(100, 740)
    for line in rec.split('\n'):
        text.textLine(line)
    p.drawText(text)
    p.showPage()
    p.save()
    buffer.seek(0)
    g3 = get_predictor_model().predict(df_input)[0]
    risk = get_classifier_model().predict(df_input)[0]
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'attachment; filename=prediction_report.pdf'
    return response\

#-- student_view their attendance --#

@app.route('/attendance')
@role_required('student')
def view_attendance():
    records = Attendance.query.filter_by(student_id=session['user_id'])\
                              .order_by(Attendance.date.desc()).all()
    return render_template('attendance.html', records=records)
 #--- My assessment-----   

@app.route('/my-assessments')
@role_required('student')
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
