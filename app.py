from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
#from study_recommendation import generate_recommendations
from ML.study_recommendation  import generate_recommendation

app = Flask(__name__)
CORS(app)

# Load both models
at_risk_model = joblib.load('ML/light_at_risk_classifier_model.joblib')
grade_predictor_model = joblib.load('ML/light_student_performance_predictor_model.joblib')  

# Feature validation (same for both models)
EXPECTED_FEATURES = ['G1', 'G2', 'failures', 'absences', 'higher', 
                    'studytime', 'age', 'Dalc', 'goout']

def preprocess_input(data):
    """Shared preprocessing for both models"""
    return [data[feat] if feat != 'higher' else (1 if data[feat].lower() == 'yes' else 0)
            for feat in EXPECTED_FEATURES]

# endpoint for grade prediction
@app.route('/predict-grade', methods=['POST'])
def predict_grade():
    try:
        data = request.json
        
        # Validate input
        missing = [feat for feat in EXPECTED_FEATURES if feat not in data]
        if missing:
            return jsonify({"error": f"Missing features: {missing}"}), 400

        # Preprocess and predict
        input_data = preprocess_input(data)
        g3_pred = grade_predictor_model.predict([input_data])[0]
        
        return jsonify({
            "predicted_grade": round(float(g3_pred), 2),  # Round to 2 decimal places
            "at_risk_threshold": 7.5  # Optional: include threshold context
        })
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Existing at-risk endpoint (modified to use shared preprocessing)
@app.route('/predict-at-risk', methods=['POST'])
def predict_at_risk():
    try:
        data = request.json
        missing = [feat for feat in EXPECTED_FEATURES if feat not in data]
        if missing:
            return jsonify({"error": f"Missing features: {missing}"}), 400

        input_data = preprocess_input(data)
        prediction = at_risk_model.predict([input_data])[0]
        probability = at_risk_model.predict_proba([input_data])[0][1]

        return jsonify({
            "at_risk": bool(prediction),
            "probability": round(float(probability), 2),
            "threshold": 7.5
        })
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Recommendations endpoint 
@app.route('/get-recommendations', methods=['POST'])
def get_recommendations():
    try:
        data = request.json
        recommendations = generate_recommendations(
            studytime=data['studytime'],
            failures=data['failures'],
            absences=data['absences'],
            dalc=data['Dalc'],
            goout=data['goout']
        )
        return jsonify(recommendations)
    except KeyError as e:
        return jsonify({"error": f"Missing key: {str(e)}"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)