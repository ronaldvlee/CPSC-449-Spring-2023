from flask import Flask, redirect, render_template, url_for, request, session, abort
from datetime import timedelta

app = Flask(__name__)
app.secret_key = "hello"
app.permanent_session_lifetime = timedelta(minutes=10)

@app.route("/")
def home():
    return redirect(url_for('login'))
    # return render_template("index.html")

@app.route("/login", methods = ['GET','POST'])
def login():
    if request.method == 'POST':
        session.permanent = 'remember' in request.form
        user = request.form['username']
        session['user'] = user
        return redirect(url_for('profile'))
    else:
        if 'user' in session:
            return redirect(url_for('profile'))
        return render_template("login.html")

@app.route("/profile")
def profile():
    if 'user' in session:
        user = session['user']
        if user == 'admin':
            return redirect(url_for('admin'))
        return render_template("profile.html", data = session)
    else:
        return redirect(url_for('login'))
    
@app.route('/admin')
def admin():
    if 'user' in session and session['user'] == 'admin':
        return '<h1>Hello admin</h1>'
    else:
        abort(401)

@app.errorhandler(401)
def unauthorized(error):
    return f'<h1>401 - unauthorized</h1>'

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))
