from http import HTTPStatus
from flask import Flask, abort, request, send_from_directory, make_response, render_template, url_for, redirect
from werkzeug.datastructures import WWWAuthenticate
import flask
from json import dumps, loads
from base64 import b64decode
import sys
import apsw
from apsw import Error
from pygments import highlight
from pygments.lexers import SqlLexer
from pygments.formatters import HtmlFormatter
from pygments.filters import NameHighlightFilter, KeywordCaseFilter
from pygments import token;
from threading import local
from markupsafe import escape
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import secrets
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
import flask_login
from flask_login import login_required, login_user, UserMixin
import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_urlsafe(16)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///userdata.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

tls = local()
cssData = HtmlFormatter(nowrap=True).get_style_defs('.highlight')

# Add a login manager to the app

login_manager = flask_login.LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# Class to store user info
# UserMixin provides us with an `id` field and the necessary
# methods (`is_authenticated`, `is_active`, `is_anonymous` and `get_id()`)
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

with app.app_context():
    db.create_all()

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], 
        render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], 
        render_kw={"placeholder": "Password"})
    submit = SubmitField("Register")

    def validate_username(self, username):
        username_exists = User.query.filter_by(
        username=username.data).first()

        if username_exists:
            raise ValidationError(
                "Username already exists, try again."
            )


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], 
        render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], 
        render_kw={"placeholder": "Password"})
    submit = SubmitField("Login") 



# This method is called whenever the login manager needs to get
# the User object for a given user id
@login_manager.user_loader
def user_loader(user_id):
    return User.query.get(int(user_id))



def pygmentize(text):
    if not hasattr(tls, 'formatter'):
        tls.formatter = HtmlFormatter(nowrap = True)
    if not hasattr(tls, 'lexer'):
        tls.lexer = SqlLexer()
        tls.lexer.add_filter(NameHighlightFilter(names=['GLOB'], tokentype=token.Keyword))
        tls.lexer.add_filter(NameHighlightFilter(names=['text'], tokentype=token.Name))
        tls.lexer.add_filter(KeywordCaseFilter(case='upper'))
    return f'<span class="highlight">{highlight(text, tls.lexer, tls.formatter)}</span>'

@app.route('/favicon.ico')
def favicon_ico():
    return send_from_directory(app.root_path, 'favicon.ico', mimetype='image/vnd.microsoft.icon')

@app.route('/favicon.png')
def favicon_png():
    return send_from_directory(app.root_path, 'favicon.png', mimetype='image/png')


@app.route('/')
@app.route('/index')
@login_required
def index_html():
    return send_from_directory(app.root_path,
                        'index.html', mimetype='text/html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    else:
        return render_template('./register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                flask.flash('Logged in successfully.')
                return redirect(url_for('index_html'))
    else:    
        return render_template('./login.html', form=form)

            
@app.get('/search')
def search():
    user = flask_login.current_user.username
    query = request.args.get('q') or request.form.get('q')
    stmt = f"SELECT * FROM messages WHERE message LIKE '{query}' AND (sender='{user}' OR receiver='{user}')"
    result = f"Query: {pygmentize(stmt)}\n"
    try:
        c = conn.execute(stmt)
        rows = c.fetchall()
        result = result + 'Result:\n'
        for row in rows:
            result = f'{result}    {dumps(row)}\n'
        c.close()
        return result
    except Error as e:
        return (f'{result}ERROR: {e}', 500)

@app.get('/show')
def show():
    user = flask_login.current_user.username
    stmt = f"SELECT * FROM messages WHERE sender='{user}' OR receiver='{user}'"
    result = f"Query: {pygmentize(stmt)}\n"
    try:
        c = conn.execute(stmt)
        rows = c.fetchall()
        result = result + 'Result:\n'
        for row in rows:
            result = f'{result}    {dumps(row)}\n'
        c.close()
        return result
    except Error as e:
        return (f'{result}ERROR: {e}', 500)


@app.route('/send', methods=['POST','GET'])
def send():
    try:
        time = datetime.datetime.now()
        sender = flask_login.current_user.username
        receiver = request.args.get('receiver') or request.form.get('receiver')
        message = request.args.get('message') or request.args.get('message')
        if not receiver or not message:
            return f'ERROR: missing receiver or message'
        if not User.query.filter_by(username=receiver).first():
            return f'ERROR: user not found'
        stmt = f"INSERT INTO messages (time, sender, receiver, message) values ('{time}', '{sender}', '{receiver}', '{message}');"
        result = f"Query: {pygmentize(stmt)}\n"
        conn.execute(stmt)
        return f'{result}ok'
    except Error as e:
        return f'{result}ERROR: {e}'

@app.get('/announcements')
def announcements():
    try:
        stmt = f"SELECT author,text FROM announcements;"
        c = conn.execute(stmt)
        anns = []
        for row in c:
            anns.append({'sender':escape(row[0]), 'message':escape(row[1])})
        return {'data':anns}
    except Error as e:
        return {'error': f'{e}'}

@app.get('/highlight.css')
def highlightStyle():
    resp = make_response(cssData)
    resp.content_type = 'text/css'
    return resp

try:
    conn = apsw.Connection('./tiny.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS messages (
        id integer PRIMARY KEY, 
        time DATETIME,
        sender VARCHAR(20),
        receiver VARCHAR(20),
        message TEXT NOT NULL);''')
    c.execute('''CREATE TABLE IF NOT EXISTS announcements (
        id integer PRIMARY KEY, 
        author TEXT NOT NULL,
        text TEXT NOT NULL);''')
except Error as e:
    print(e)
    sys.exit(1)

if __name__ == '__main__':
    app.run()