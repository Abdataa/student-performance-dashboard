from flask import Flask, render_template, request
import joblib

app = Flask(__name__)
model = joblib.load('ML/model_try1.pkl')

@app.route('/')
def home():
    return render_template('index.html')  # Renders your form

@app.route('/predict', methods=['POST'])
def predict():
    # Get scores from the form
    math = float(request.form['math_score'])
    reading = float(request.form['reading_score'])
    writing = float(request.form['writing_score'])

    # Predict grade
    prediction = model.predict([[math, reading, writing]])[0]

    # Pass scores AND prediction to result.html
    return render_template('result.html', 
                          grade=prediction,
                          math=math,
                          reading=reading,
                          writing=writing)
if __name__ == '__main__':
    app.run(debug=True)                          