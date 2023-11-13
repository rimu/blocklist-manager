from flask import Flask
from config import Config
from flask import render_template, flash, redirect, url_for, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime
from flask_wtf import FlaskForm
from wtforms import SubmitField, TextAreaField, StringField, PasswordField
from wtforms.validators import ValidationError, DataRequired, Email, EqualTo, Length
from utils import get_ip_address
from validators import domain
import os
from flask_login import LoginManager, current_user, login_user, logout_user, current_user, login_required
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.urls import url_parse

app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login = LoginManager(app)
login.login_view = 'login'


@login.user_loader
def load_user(id):
    return User.query.get(int(id))


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    submissions = db.relationship('PendingSubmission', backref='author', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return '<User {}>'.format(self.username)


class PendingSubmission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(1024))
    created = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(50))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __repr__(self):
        return '<Submission {}>'.format(self.url[0:10])


@app.route('/')
def index():

    file = open(app.config['DATASTORE'] + '/dnsmasq_hosts.txt')
    lines = file.read().splitlines()
    file.close()
    final_lines = []
    for line in lines:
        parts = line.strip().split(' ')
        if len(parts) == 3:
            final_lines.append(parts[1])
    return render_template('home.html', lines=final_lines)


@app.route('/add_to_blocklist', methods=['GET', 'POST'])
def add_to_blocklist():
    form = AddToBlocklistForm()

    if form.validate_on_submit():
        if form.fake_email.data != '':   # guard against spam. This field is hidden using CSS so a human would never fill it out.
            return redirect(url_for('add_to_blocklist'))
        ip_address = get_ip_address()
        for line in form.url.data.split("\n"):
            if len(line.strip()) > 0:
                new_submission = PendingSubmission()
                line = line.strip().lower().replace('https://', '').replace('http://', '').replace('www.', '')
                if domain(line):
                    new_submission.url = line
                    new_submission.ip_address = ip_address
                    db.session.add(new_submission)
                else:
                    flash(line + ' not added', 'warning')
        db.session.commit()
        flash('Thank you, these urls will be added to the blocklist after they have been verified.', 'success')
        return redirect(url_for('add_to_blocklist'))

    return render_template('add_to_blocklist.html', title='Add to blocklist', form=form)


@app.route('/list_submissions', methods=['GET', 'POST'])
@login_required
def list_submissions():
    if request.method == 'POST':
        added = 0
        already_exists = 0
        deleted = 0
        for key in request.values:
            if 'checkbox_' in str(key):
                parts = key.split('_')
                if request.values['operation'] == 'Approve':
                    result = approve_pending_submission(parts[1])
                    if result == 1:
                        added = added + 1
                    elif result == -1:
                        already_exists = already_exists + 1
                db.session.query(PendingSubmission).filter(PendingSubmission.id == parts[1]).delete()
                if request.values['operation'] == 'Delete':
                    deleted = deleted + 1
        db.session.commit()

        if added > 0:
            flash(str(added) + ' added.', 'success')
            today = datetime.now().date()
            if request.values['commit_message'] != '':
                commit_message = request.values['commit_message']
            else:
                commit_message = 'update ' + str(today)
            dirname = os.path.dirname(__file__)
            full_path = os.path.join(dirname, app.config['DATASTORE'])
            return_value = os.system('cd ' + full_path + ' && ' + full_path + '/update "' + commit_message + '"')
            if return_value != 0:
                flash('update command returned a non-zero result', 'warning')

        if deleted > 0:
            flash(str(deleted) + ' deleted.', 'success')
        if already_exists > 0:
            flash(str(already_exists) + ' already exist in the list and were skipped.')

    submissions = PendingSubmission.query.all()
    return render_template('list_submissions.html', title='Submissions', submissions=submissions)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.user_name.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        login_user(user, remember=True)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('index')
        return redirect(next_page)
    return render_template('login.html', title='Sign In', form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        if form.email.data == '':  # ignore any registration where the email field is filled out. spam prevention
            user = User(username=form.user_name.data, email=form.real_email.data)
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.commit()
        flash('Congratulations, you are now a registered user! Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)



class AddToBlocklistForm(FlaskForm):
    url = TextAreaField('URLs, one per line', render_kw={"rows": 7, "class": "form-control"}, validators=[DataRequired(), Length(min=1, max=15000)])
    fake_email = StringField('Email')
    submit = SubmitField('Add', render_kw={"class": "btn btn-primary"})


class LoginForm(FlaskForm):
    user_name = StringField('User name', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign In', render_kw={"class": "btn btn-primary"})


class RegistrationForm(FlaskForm):
    user_name = StringField('User name / login', validators=[DataRequired()])
    email = StringField('Email')
    real_email = StringField('Email', validators=[DataRequired(), Email(), Length(min=5, max=255)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=5, max=50)])
    password2 = PasswordField(
        'Repeat password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register', render_kw={"class": "btn btn-primary"})

    def validate_real_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('An account with this email address already exists.')


class ResetPasswordRequestForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request password reset', render_kw={"class": "btn btn-primary"})


class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField(
        'Repeat password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Request password reset', render_kw={"class": "btn btn-primary"})


def approve_pending_submission(value):
    p = PendingSubmission.query.get(value)
    file = open(app.config['DATASTORE'] + '/dnsmasq_hosts.txt')
    lines = file.read().splitlines()
    file.close()
    for line in lines:
        if p.url in line:
            return -1   # already exists

    file = open(app.config['DATASTORE'] + '/dnsmasq_hosts.txt', 'a')
    file.write('0.0.0.0 ' + p.url + ' www.' + p.url + "\n")
    file.close()

    return 1



if __name__ == '__main__':
    app.run()
