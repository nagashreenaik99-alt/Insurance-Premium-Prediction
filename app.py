import numpy as np
from flask import Flask,render_template,request,session,redirect,url_for,flash, jsonify
import pickle
import uuid
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from hashlib import sha256

#creating object for flask
app=Flask(__name__)
app.secret_key='your_secret_key'

import pickle

# load model
with open('insurance.pkl', 'rb') as f:
    model = pickle.load(f)


# SQLite database path and helper
DB_PATH = 'users.db'

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    cur.close()
    conn.close()

def hash_password(password):
    return sha256(password.encode()).hexdigest()

#prediction
def predict_score(Age=36,Diabetes=1,BloodPressureProblems=0,AnyTransplants=0,AnyChronicDiseases=1,Height=180,Weight=57,KnownAllergies=1,HistoryOfCancerInFamily=1,NumberOfMajorSurgeries=2):
    temp_array=list()
    temp_array=temp_array+[Age,Diabetes,BloodPressureProblems,AnyTransplants,AnyChronicDiseases,Height,Weight,KnownAllergies,HistoryOfCancerInFamily,NumberOfMajorSurgeries]

    #converting into numpy array
    temp_array = np.array([temp_array])

    # prediction using loaded model
    try:
        pred = model.predict(temp_array)
        # ensure single value
        return int(pred[0])
    except Exception as e:
        print('Prediction error:', e)
        raise

@app.route('/')
def home():
    # If user is logged in, show prediction page; otherwise show login first
    if 'username' in session:
        return render_template('prediction.html')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # support JSON (from our registration.html) and form submissions
        if request.is_json:
            data = request.get_json()
            username = data.get('email') or data.get('username')
            password = data.get('password')
        else:
            username = request.form.get('email') or request.form.get('username')
            password = request.form.get('password')

        if not username or not password:
            return (jsonify({'message': 'Missing username/email or password'}), 400) if request.is_json else (flash('Missing fields', 'danger'), redirect(url_for('register')))[1]

        # use Werkzeug's default secure hashing (do not pass plain 'sha256')
        hashed_password = generate_password_hash(password)

        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
            conn.commit()
        except sqlite3.IntegrityError:
            cursor.close()
            conn.close()
            if request.is_json:
                return (jsonify({'message':'Email already registered'}), 400)
            flash('Email already registered', 'danger')
            return redirect(url_for('register'))

        cursor.close()
        conn.close()

        if request.is_json:
            return jsonify({'message': 'Registered', 'redirect': url_for('login')})
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('registration.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.is_json:
            data = request.get_json()
            username = data.get('email') or data.get('username')
            password = data.get('password')
        else:
            username = request.form.get('email') or request.form.get('username')
            password = request.form.get('password')

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE username=?", (username,))
        result = cursor.fetchone()
        cursor.close()
        conn.close()

        if result and check_password_hash(result[0], password):
            session['username'] = username
            if request.is_json:
                return jsonify({'message': 'Login successful', 'redirect': url_for('dashboard')})
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            if request.is_json:
                return (jsonify({'message': 'Invalid username or password'}), 401)
            flash('Invalid username or password', 'danger')

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template('dashboard.html', username=session['username'])
    else:
        flash('Please log in to access the dashboard', 'warning')
        return redirect(url_for('login'))


@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('Logged out', 'info')
    return redirect(url_for('home'))
@app.route('/predict',methods=['GET','POST'])
def predict():
    # Block access if not logged in
    if 'username' not in session:
        if request.method == 'POST' and request.is_json:
            return (jsonify({'message':'Authentication required'}), 401)
        flash('Please log in to make predictions', 'warning')
        return redirect(url_for('login'))

    if request.method == 'POST':
        # support JSON payloads (from index.html) or form submissions
        if request.is_json:
            data = request.get_json()
            Age = int(data.get('Age', 36))
            Diabetes = int(data.get('Diabetes', 1))
            BloodPressureProblems = int(data.get('BloodPressureProblems', 0))
            AnyTransplants = int(data.get('AnyTransplants', 0))
            AnyChronicDiseases = int(data.get('AnyChronicDiseases', 1))
            Height = int(data.get('Height', 180))
            Weight = int(data.get('Weight', 57))
            KnownAllergies = int(data.get('KnownAllergies', 1))
            HistoryOfCancerInFamily = int(data.get('HistoryOfCancerInFamily', 1))
            NumberOfMajorSurgeries = int(data.get('NumberOfMajorSurgeries', 2))
        else:
            Age = int(request.form.get('Age', 36))
            Diabetes = int(request.form.get('Diabetes', 1))
            BloodPressureProblems = int(request.form.get('BloodPressureProblems', 0))
            AnyTransplants = int(request.form.get('AnyTransplants', 0))
            AnyChronicDiseases = int(request.form.get('AnyChronicDiseases', 1))
            Height = int(request.form.get('Height', 180))
            Weight = int(request.form.get('Weight', 57))
            KnownAllergies = int(request.form.get('KnownAllergies', 1))
            HistoryOfCancerInFamily = int(request.form.get('HistoryOfCancerInFamily', 1))
            NumberOfMajorSurgeries = int(request.form.get('NumberOfMajorSurgeries', 2))

        prediction = predict_score(Age, Diabetes, BloodPressureProblems, AnyTransplants, AnyChronicDiseases, Height, Weight, KnownAllergies, HistoryOfCancerInFamily, NumberOfMajorSurgeries)

        if request.is_json:
            return jsonify({'prediction': prediction})
        return render_template('result.html', prediction=prediction)

    return render_template('index.html')

if __name__ == '__main__':
    # ensure DB exists
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
