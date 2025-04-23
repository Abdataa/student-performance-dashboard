from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import joblib
import pandas as pd
import numpy as np
from ML import study_recommendation

app = Flask(__name__)

app.secret_key = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///student_performance.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///student_performance.db'  # Make sure this is correct
db = SQLAlchemy(app)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    is_active = db.Column(db.Boolean, default=True)

    def __repr__(self):
        return f'<User {self.email}>'

# Create the database tables if they don't exist
with app.app_context():
    db.create_all()  



# --- Model Setup ---
# Load models
predictor_model = joblib.load("ML/light_student_performance_predictor_model.joblib")
classifier_model = joblib.load("ML/light_at_risk_classifier_model.joblib")

# Define expected features for prediction
input_features = ['G1', 'G2', 'failures', 'absences', 'higher', 'studytime', 'age', 'Dalc', 'goout']

# --- Helper Functions ---
def encode_inputs(data):
    encoded = data.copy()
    # Convert categorical features as done in training
    encoded['higher'] = 1 if encoded['higher'] == 'yes' else 0
    return encoded

# Define the User model here if not done already...

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email    = request.form['email']
        password = request.form['password']
        role     = request.form['role']

        # Check for existing user
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered', 'error')
            return redirect(url_for('register'))

        # Hash the password
        hashed_pw = generate_password_hash(password)

        # Create User using correct field names
        new_user = User(
            username=username,
            email=email,
            password_hash=hashed_pw,
            role=role
        )
        db.session.add(new_user)
        db.session.commit()

        flash('Registered successfully. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']  # Get email from form
        password = request.form['password']
         # Changed from filter to filter_by(email=email)
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['role']    = user.role
            session['username']= user.username
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials', 'error')
            return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return f"Welcome, user {session['user_id']} with role {session['role']}!"


# --- Prediction Routes ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    if 'user_id' not in session:
        flash('Please login to access this feature', 'danger')
        return redirect(url_for('login'))
    
    try:
        # Extract form data
        data = {feature: request.form.get(feature) for feature in input_features}

        # Convert numeric values (excluding categoricals)
        for key in ['G1', 'G2', 'failures', 'absences', 'studytime', 'age', 'Dalc', 'goout']:
            data[key] = float(data[key]) if data[key] else 0.0

        # Encode categorical features
        data_encoded = encode_inputs(data)

        # Convert to DataFrame
        input_df = pd.DataFrame([data_encoded])

        # Predict grade (G3)
        predicted_grade = predictor_model.predict(input_df)[0]

        # Classify risk
        risk_status = classifier_model.predict(input_df)[0]
        risk_status_str = "At Risk" if risk_status == 1 else "Not At Risk"

        # Get recommendation
        recommendation = study_recommendation.generate_recommendation(input_df.iloc[0])

        return render_template('result.html',
                            predicted_grade=round(predicted_grade, 2),
                            risk_status=risk_status_str,
                            recommendation=recommendation)
    
    except Exception as e:
        flash(f'Error during prediction: {e}', 'danger')
        return redirect(url_for('student_dashboard'))

if __name__ == '__main__':
    app.run(debug=True)
