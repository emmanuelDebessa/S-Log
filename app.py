from flask import Flask,request,redirect,flash
from wtforms import Form, BooleanField, StringField, PasswordField, validators
from flask import render_template
##from forms import InputLabels, Signin
from flask_wtf.csrf import CSRFProtect
from flask_sqlalchemy import SQLAlchemy
from flask import Flask, render_template,request,redirect,url_for
from flask_bootstrap import Bootstrap
from flask_moment import Moment
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from _datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from wtforms import ValidationError
from flask_login import LoginManager
from flask_login import current_user, login_user
from flask_login import login_required
from flask_login import UserMixin

from wtforms.validators import length,email,email_validator,equal_to
app = Flask(__name__)
application = app

app.config['SECRET_KEY'] = 'hello123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Recipe.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
bootstrap = Bootstrap(app)
moment = Moment(app)
migrate = Migrate(app, db)
login = LoginManager(app)
login.login_view = 'sign'







class Friends(db.Model,UserMixin):
    id = db.Column(db.INTEGER,primary_key=True)
    email = db.Column(db.String(200),nullable = False)
    user = db.Column(db.String(200),nullable = False)
    password = db.Column(db.String(200),nullable = False)
    password_hash = db.Column(db.String(200),nullable = False)



    def __repr__(self):
        return '<Email %r>' % self.email

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @login.user_loader
    def load_user(id):
        return Friends.query.get(int(id))





class InputLabels(FlaskForm):
    email = StringField("Email",[validators.length(min=5,message="Length must be 5+"),validators.email(message="Must be email")])

    user = StringField("Username",[validators.DataRequired("Required")])


    password = PasswordField('New Password',[validators.EqualTo('confirmation', message='Passwords must match'),validators.DataRequired("Required")])
    confirmation = PasswordField('Repeat Password',[validators.DataRequired("Required")])
    submit = SubmitField("Sign up")

    accept_tos = BooleanField("By Clicking here you agree to our TOS", [validators.DataRequired("Must click so we do not get sued")])

    def validate_user(self,user):
        email = Friends.query.filter_by(user=user.data).first()
        if email != None:
            raise ValidationError('That Username is taken. Please choose another.')


    def validate_email(self,email):
        email= Friends.query.filter_by(email=email.data).first()
        if email != None:
             raise ValidationError('That email is taken. Please choose another.')


class Signin(FlaskForm):
    user = StringField("Username",[validators.DataRequired("gg")])
    password = PasswordField(' Password', [validators.DataRequired("Test")])
    submit = SubmitField("Log in")








 ## @login_required


@app.route('/',methods=['GET','POST'])

def hi():
    form = InputLabels()

    if(form.validate_on_submit()):
        user =request.form['user']
        email = request.form['email']
        password = request.form['password']
        user1 = Friends(user=user, email=email,password=password)
        user1.set_password(password)
        db.session.add(user1)
        db.session.commit()

        return render_template("Flask_Form.html",Username = user)








    return render_template('h.html',form= form)



@app.route('/Signin',methods=['GET','POST'])
def sign():
    if current_user.is_authenticated:
        print("hello")
    form = Signin()

    if (form.validate_on_submit()):
        result = request.form['user']
        user = Friends.query.filter_by(user=result).first()
        if user is None or not user.check_password(request.form['password']):

            flash("Invalid Username or Password")
            return render_template('Login.html', form=form)

#        login_user(user, remember=True)
        login_user(user)

        return redirect(url_for('profile'))


    return render_template('Login.html', form = form)

@app.route('/Profile',methods=['GET','POST'])
def profile():
    return render_template("Homepage.html")


if __name__ == '__main__':
    app.run()
