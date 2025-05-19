from flask import Flask, render_template,render_template_string, request, jsonify, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
import sys
import io
import os
import hashlib

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    codes = db.relationship('Code', backref='user', lazy=True)



class Code(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    code = db.Column(db.Text, nullable=False)
    name = db.Column(db.String(100), nullable=False)

    def __init__(self, user_id, code, name):
        self.user_id = user_id
        self.code = code
        self.name = name

@app.route('/')
def index():
    code_id = request.args.get('code_id')
    return render_template('index.html', code_id=code_id)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = hashlib.md5(request.form['password'].encode()).hexdigest()
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('User already exists. Please choose a different username.')
        else:
            new_user = User(username=username, password=password)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! You can now log in.')
            return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = hashlib.md5(request.form['password'].encode()).hexdigest()
        user = User.query.filter_by(username=username, password=password).first()
        if user:
            session['user_id'] = user.id
            flash('Login successful!')
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials. Please try again.')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.')
    return redirect(url_for('index'))

@app.route('/run_code', methods=['POST'])
def  run_code():
    code = request.form['code']
    old_stdout = sys.stdout
    redirected_output = sys.stdout = io.StringIO()
    try:
        for keyword in ['eval', 'exec', 'import', 'open', 'os', 'read', 'system', 'write', 'subprocess', '__import__', '__builtins__']:
            if keyword in code.lower():
                return jsonify({'output': 'Use of restricted keywords is not allowed.'})
        exec(code)
        output = redirected_output.getvalue()
    except Exception as e:
        output = str(e)
    finally:
        sys.stdout = old_stdout
    return jsonify({'output': output})

@app.route('/load_code/<int:code_id>')
def load_code(code_id):
    if 'user_id' not in session:
        flash('You must be logged in to view your codes.')
        return redirect(url_for('login'))
    code = Code.query.get_or_404(code_id)
    if code.user_id != session['user_id']:
        flash('You do not have permission to view this code.')
        return redirect(url_for('codes'))
    return jsonify({'code': code.code})


@app.route('/save_code', methods=['POST'])
def save_code():
    if 'user_id' not in session:
        return jsonify({'message': 'You must be logged in to save code.'}), 401
    user_id = session['user_id']
    code = request.form.get('code')
    name = request.form.get('name')
    if not code or not name:
        return jsonify({'message': 'Code and name are required.'}), 400
    new_code = Code(user_id=user_id, code=code, name=name)
    db.session.add(new_code)
    db.session.commit()
    return jsonify({'message': 'Code saved successfully!'})


@app.route('/codes', methods=['GET', 'POST'])
def codes():

    if 'user_id' not in session:
        flash('You must be logged in to view your codes.')
        return redirect(url_for('login'))

    user_id = session['user_id']
    codes = Code.query.filter_by(user_id=user_id).all()

    if request.method == 'POST':
        code_id = request.form.get('code_id')
        code = Code.query.get(code_id)
        if code and code.user_id == user_id:
            db.session.delete(code)
            db.session.commit()
            flash('Code deleted successfully!')
        else:
            flash('Code not found or you do not have permission to delete it.')
        return redirect(url_for('codes'))     
    return render_template('codes.html',codes=codes)


@app.route('/about')
def about():
    return render_template('about.html')

if __name__ == '__main__':
    if not os.path.exists('database.db'):
        with app.app_context():
            db.create_all()
    app.run(host='0.0.0.0', port=5000)
