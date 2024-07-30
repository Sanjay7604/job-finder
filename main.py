import os
from flask import Flask, render_template, redirect, url_for, flash, abort,request
from flask_bootstrap import Bootstrap
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_gravatar import Gravatar
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, IntegerField
from wtforms.validators import DataRequired, URL
from functools import wraps
from sqlalchemy import Table, Column, Integer, ForeignKey,create_engine,text
from flask_ckeditor import CKEditor, CKEditorField

os.environ["SECRET_KEY"] = "271092u40932092"

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
login_manager = LoginManager()
login_manager.init_app(app)
Bootstrap(app)
ckeditor = CKEditor(app)



##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL", "sqlite:///job.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
engine=create_engine("sqlite:///job.db")

##DECORATOR

def employer_only(f):
    @wraps(f)
    def decorated_function(*args,**kwargs):
        if current_user.status!=0:
            return abort(403)
        return f(*args,**kwargs)
    return decorated_function


##TABLE

class User(UserMixin, db.Model):
    __tablename__="users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(200), unique=True)
    name = db.Column(db.String(200))
    organization_name = db.Column(db.String(200))
    password = db.Column(db.String(200))
    address = db.Column(db.String(200))
    about = db.Column(db.String(500))
    status = db.Column(db.Integer)
    profile_pic = db.Column(db.String(100), default="Default_profile.png")
    jobs=relationship("Jobs",back_populates="author")

class Jobs(db.Model):
    __tablename__="jobs"
    id=db.Column(db.Integer,primary_key=True)
    job_title=db.Column(db.String(100))
    description=db.Column(db.String(200))
    author_id=db.Column(db.Integer,ForeignKey("users.id"))
    author=relationship("User",back_populates="jobs")


# class Employee(UserMixin, db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     email = db.Column(db.String(200), unique=True)
#     name = db.Column(db.String(200))
#     password = db.Column(db.String(200))
#     about = db.Column(db.String(500))
#     status = db.Column(db.String(20))


db.create_all()


##WTFORM

class RegisterFormEmployer(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    organization_name = StringField("Organization Name", validators=[DataRequired()])
    about = CKEditorField("About", validators=[DataRequired()])
    address = CKEditorField("Address", validators=[DataRequired()])
    submit = SubmitField("Go")


class RegisterFormEmployee(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    about = CKEditorField("About", validators=[DataRequired()])
    submit = SubmitField("Go")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


class JobForm(FlaskForm):
    job_title = StringField("Job Title", validators=[DataRequired()])
    description= CKEditorField("Description",validators=[DataRequired()])
    submit=SubmitField("Post")


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def home():
    if current_user.is_authenticated:
        if current_user.status==1:
            return render_template("home_employee.html",logged_in=current_user.is_authenticated)
        else:
            return render_template("index.html",logged_in=current_user.is_authenticated)

    return render_template("index.html",logged_in=current_user.is_authenticated)


@app.route('/choice')
def choice_login():
    return render_template("choice_login.html",logged_in=current_user.is_authenticated)


@app.route('/choicer')
def choice_register():
    return render_template("choice_register.html",logged_in=current_user.is_authenticated)


@app.route('/login/<i>', methods=["POST", "GET"])
def login(i):
    form = LoginForm()
    i = int(i)
    if form.validate_on_submit():
        email = form.email.data
        print(email)
        password = form.password.data
        if i == 1:
            user = db.session.query(User).filter_by(email=email).first()               ##employee
            if not user:
                flash("This email does not exist, please try again")
                return redirect(url_for('login', i=1))
            elif not check_password_hash(user.password, password):
                flash("Password incorrect, please try again")
                return redirect(url_for('login', i=1))
            elif i != user.status:
                flash("You are an employer.")
                return redirect(url_for('login', i=1))
            else:
                login_user(user)
                return redirect(url_for('home'))
        if i == 0:
            user = db.session.query(User).filter_by(email=email).first()                     ##employer
            if not user:
                flash("This email does not exist, please try again")
                return redirect(url_for('login', i=0))
            elif not check_password_hash(user.password, password):
                flash("Password incorrect, please try again")
                return redirect(url_for('login', i=0))
            elif i != user.status:
                flash("You are an employee.")
                return redirect(url_for('login', i=0))
            else:
                login_user(user)
                return redirect(url_for('home'))
    return render_template('login.html', form=form,logged_in=current_user.is_authenticated)


@app.route('/register/<int:i>', methods=["POST", "GET"])
def register(i):
    if i == 1:
        form = RegisterFormEmployee()
        if form.validate_on_submit():
            email = form.email.data
            user = db.session.query(User).filter_by(email=email).first()
            if user:
                flash("You've already signed up with that email, login instead.")
                return redirect(url_for('register', i=1))
            new_user = User()
            new_user.email = email
            new_user.password = generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=8)
            new_user.name = form.name.data
            new_user.status = 1
            new_user.about = form.about.data
            new_user.organization_name=None
            new_user.address=None
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('home'))
        return render_template('register.html', form=form,logged_in=current_user.is_authenticated)
    else:
        form = RegisterFormEmployer()
        if form.validate_on_submit():
            email = form.email.data
            user = db.session.query(User).filter_by(email=email).first()
            if user:
                flash("You've already signed up with that email, login instead.")
                return redirect(url_for('register', i=0))
            new_user = User()
            new_user.email = email
            new_user.password = generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=8)
            new_user.name = form.name.data
            new_user.status = 0
            new_user.organization_name = form.organization_name.data
            new_user.about = form.about.data
            new_user.address = form.address.data
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('home'))
        return render_template("register.html", form=form,logged_in=current_user.is_authenticated)


@app.route('/details',methods=["POST","GET"])
@login_required
def details():
    if request.method=="POST":
        img=request.files['profile-pic']
        if not current_user.profile_pic=="Default_profile.png":
            os.remove(f"static/img/{current_user.email}.png")
        img.save(f'static/img/{current_user.email}.png')
        current_user.profile_pic=f'{current_user.email}.png'
        db.session.commit()
        return redirect(url_for('details'))
    return render_template('details.html', logged_in=current_user.is_authenticated)

@app.route('/login')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/add',methods=["POST","GET"])
@login_required
@employer_only
def add_job():
    form=JobForm()
    if form.validate_on_submit():
        new_job=Jobs()
        new_job.job_title=form.job_title.data
        new_job.description=form.description.data
        new_job.author=current_user
        db.session.add(new_job)
        db.session.commit()
        return redirect(url_for('home'))
    return render_template('add_job.html',logged_in=current_user.is_authenticated,form=form)

@app.route('/joblist',methods=["POST","GET"])
@login_required
@employer_only
def job_list():
    return render_template('job_list.html',jobs=current_user.jobs,logged_in=current_user.is_authenticated)

@app.route('/delete/<i>',methods=["POST","GET"])
@login_required
@employer_only
def delete_job(i):
    id=int(i)
    job=Jobs.query.get(id)
    db.session.delete(job)
    db.session.commit()
    return redirect(url_for('job_list'))

@app.route('/job_0/<i>')
@login_required
def view_job(i):
    id=int(i)
    job=Jobs.query.get(id)
    return render_template('job_employer.html',job=job,logged_in=current_user.is_authenticated)


@app.route('/edit_job/<i>',methods=["POST","GET"])
@login_required
@employer_only
def edit_job(i):
    id=int(i)
    job = Jobs.query.get(id)
    form=JobForm(job_title=job.job_title,description=job.description)
    if form.validate_on_submit():
        job.job_title=form.job_title.data
        job.description=form.description.data
        db.session.commit()
        return redirect(url_for('view_job_employer',i=job.id))
    return render_template('edit_job.html',form=form,logged_in=current_user.is_authenticated)



@app.route('/search',methods=["POST","GET"])
@login_required
def search_list():
    if request.method=="POST":
        query=request.form["job-search"]
        with engine.connect() as connection:
            jobs = connection.execute(text(f"select * from Jobs where job_title like '%{query}%'"))
            return render_template('search_list.html',jobs=jobs,logged_in=current_user.is_authenticated)





if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)



