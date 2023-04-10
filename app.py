# To obtain login token..
# Username: admin
# Password: admin

from flask import Flask, abort, request, jsonify

import sqlite3
import jwt
import os

from datetime import timedelta, datetime
from werkzeug.utils import secure_filename
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = "YEP"
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'txt', 'pdf', 'png', 'jpg'}
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 # 16 MB
app.config['DATABASE_FILE'] = "users.db"

# Connect Flask application with SQLite3 database
# Create a database for users if not already generated
conn = sqlite3.connect(app.config['DATABASE_FILE'])
c = conn.cursor()

c.execute('''CREATE TABLE IF NOT EXISTS users 
            (id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL)''')

# inserts in the user admin with password admin into the database if there are no users
c.execute(f'''INSERT INTO users (username, password)
            SELECT 'admin', '{generate_password_hash('admin')}'
            WHERE NOT EXISTS (SELECT * FROM users LIMIT 1);
            ''')
conn.commit()
conn.close()

# The User Model, used to connect to the database and fetch the username
class User:
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password
    
    @staticmethod
    def get_by_username(username):
        conn = sqlite3.connect(app.config['DATABASE_FILE'])
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        row = c.fetchone()
        conn.close()
        if row is None:
            return None
        user = User(row[0], row[1], row[2])
        return user

# Task 3: Auth    
# JWT token required decorator, anything needed for auth will be decorated with @token_required
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(' ')[1]
        if not token:
            abort(401, "Token is missing!")

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        except:
            abort(401, "Token is invalid!")

        return f(*args, **kwargs)

    return decorated

# Task 4: Upload file endpoint
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
    # Get list of files in the uploads directory
    files = []
    for filename in os.listdir(app.config['UPLOAD_FOLDER']):
        path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if os.path.isfile(path):
            size = os.path.getsize(path)
            files.append({'name': filename, 'size': size})

    # Get list of users and their hashed passwords from the database
    users = []
    conn = sqlite3.connect(app.config['DATABASE_FILE'])
    cursor = conn.execute("SELECT username, password FROM users")
    for row in cursor:
        user = {'username': row[0], 'password': row[1]}
        users.append(user)
    conn.close()

    # Combine the lists of files and users into a single dictionary
    response = {'files': files, 'users': users}

    return jsonify(response)

# Task 3: Auth
# Login endpoint
@app.route('/login', methods=['POST'])
def login():
    auth = request.json

    if not auth or not auth['username'] or not auth['password']:
        return jsonify({'message': 'Could not verify!'}), 401

    user = User.get_by_username(auth['username'])

    if not user:
        return jsonify({'message': 'User does not exist!'}), 401

    # checking if the password matches the hash
    if check_password_hash(user.password, auth['password']):
        token = jwt.encode({'id': user.id, 'exp': datetime.utcnow() + timedelta(minutes=30)}, app.config['SECRET_KEY'], algorithm='HS256')
        return jsonify({'token': token}), 200

    return jsonify({'message': 'Invalid credentials!'}), 401

# Sign up endpoint
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
    
    # hash the password
    password = generate_password_hash(password)

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
    conn.commit()
    conn.close()

    return jsonify({'message': 'User created successfully'}), 201

# Task 2: Error handling
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

if __name__ == '__main__':
    app.run(debug=True)