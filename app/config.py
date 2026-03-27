import os

# Basic Config
SECRET_KEY = os.environ.get('SECRET_KEY', 'supersecretkey')
SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///student_performance.db')
SQLALCHEMY_TRACK_MODIFICATIONS = False

# Scheduler Config
SCHEDULER_JOBSTORES = {
    'default': SQLAlchemyJobStore(url=SQLALCHEMY_DATABASE_URI)
}
SCHEDULER_EXECUTORS = {
    'default': ThreadPoolExecutor(20)
}
SCHEDULER_JOB_DEFAULTS = {
    'coalesce': False,
    'max_instances': 3
}

# ML Models Path
PREDICTOR_MODEL_PATH = "../ML/light_student_performance_predictor_model.joblib"
CLASSIFIER_MODEL_PATH = "../ML/light_at_risk_classifier_model.joblib"