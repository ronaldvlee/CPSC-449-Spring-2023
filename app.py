from flask import Flask, request, jsonify

import sqlite3
import jwt
import os

from datetime import timedelta, datetime
from werkzeug.utils import secure_filename
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = "YEP"
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'txt', 'pdf', 'png', 'jpg'}
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# Connect Flask application with SQLite3 database
# Create a database for users
conn = sqlite3.connect('users.db')
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS users 
             (id INTEGER PRIMARY KEY AUTOINCREMENT,
              username TEXT NOT NULL,
              password TEXT NOT NULL)''')
conn.commit()
conn.close()

class User:
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password
    
    @staticmethod
    def get_by_username(username):
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        row = c.fetchone()
        conn.close()
        if row is None:
            return None
        user = User(row[0], row[1], row[2])
        return user
    
# JWT token required decorator, anything needed for auth will be decorated with @token_required
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(' ')[1]
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        except:
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(*args, **kwargs)

    return decorated

# Error handling
@app.errorhandler(400)
def bad_request(error):
    return jsonify({'error': 'Bad request', 'message': error.description}), 400

@app.errorhandler(401)
def unauthorized(error):
    return jsonify({'error': 'Unauthorized', 'message': error.description}), 401

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found', 'message': error.description}), 404

@app.errorhandler(500)
def internal_server_error(error):
    return jsonify({'error': 'Internal server error', 'message': error.description}), 500   

@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({'error': 'File too large!', 'message': error.description}), 413

# Upload file endpoint
@app.route('/upload', methods=['POST'])
@token_required
def upload_file():
    # Check file extension
    def allowed_file(filename):
        return '.' in filename and \
            filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']
    
    # Check if the post request has the file part
    if 'file' not in request.files:
        return jsonify({'message': 'No file part!'}), 400
    file = request.files['file']
    # If user does not select file, browser also
    # submit an empty part without filename
    if file.filename == '':
        return jsonify({'message': 'No selected file!'}), 400
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return jsonify({'message': 'File uploaded successfully!'}), 200
    else:
        return jsonify({'message': 'File not allowed!'}), 400
    
# Task 5: Public endpoint to list file names and sizes
@app.route('/public_information')
def public_information():
    files = []
    for filename in os.listdir(app.config['UPLOAD_FOLDER']):
        path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if os.path.isfile(path):
            size = os.path.getsize(path)
            files.append({'name': filename, 'size': size})
    return jsonify(files)
        
# Sign up route
@app.route('/signup', methods=['POST'])
def signup():
    username = request.json.get('username', None)
    password = request.json.get('password', None)

    if not username:
        return jsonify({'message': 'Username is required'}), 400
    if not password:
        return jsonify({'message': 'Password is required'}), 400

    user = User.get_by_username(username)
    if user:
        return jsonify({'message': 'Username already exists'}), 400

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
    conn.commit()
    conn.close()

    return jsonify({'message': 'User created successfully'}), 201

# Login endpoint
@app.route('/login', methods=['POST'])
def login():
    auth = request.json

    if not auth or not auth['username'] or not auth['password']:
        return jsonify({'message': 'Could not verify!'}), 401

    user = User.get_by_username(auth['username'])

    if not user:
        return jsonify({'message': 'User does not exist!'}), 401

    # no encryption within this api
    if user.password == auth['password']:
        token = jwt.encode({'id': user.id, 'exp': datetime.utcnow() + timedelta(minutes=30)}, app.config['SECRET_KEY'], algorithm='HS256')
        return jsonify({'token': token}), 200

    return jsonify({'message': 'Invalid credentials!'}), 401

if __name__ == '__main__':
    app.run(debug=True) 