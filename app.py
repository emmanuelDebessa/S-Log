import os
from flask import Flask, render_template, session, redirect, url_for, request
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
from itsdangerous import URLSafeTimedSerializer
from flask_login import logout_user
from flask_mail import Message
import os
from wtforms.validators import length,email,email_validator,equal_to
app = Flask(__name__)
application = app
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SECRET_KEY'] = 'hello123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Recipe.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
bootstrap = Bootstrap(app)
moment = Moment(app)
migrate = Migrate(app, db)
login = LoginManager(app)
login.login_view = 'sign'
app.config['SQLALCHEMY_BINDS'] = {
    'users': 'sqlite:///Users',
    'posts':  'sqlite:///posts'
}

app.config['SECURITY_PASSWORD_SALT'] = 'emailpass'


# other imports as necessary

class UserPosts(db.Model):
    __bind_key__ = 'posts'
    id = db.Column(db.Integer, primary_key=True)
    post_date = db.Column(db.DateTime, default=datetime.utcnow)
    post = db.Column(db.String(10,000), nullable=False)


app.config['SQLALCHEMY_DATABASE_URI'] =\
    'sqlite:///' + os.path.join(basedir, 'data.sqlite')
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

class Friends(db.Model,UserMixin):
    __bind_key__ = 'users'
    id = db.Column(db.INTEGER,primary_key=True)
    email = db.Column(db.String(200),nullable = False)
    user = db.Column(db.String(200),nullable = False)
    password = db.Column(db.String(200),nullable = False)
    password_hash = db.Column(db.String(200),nullable = False)
    authenticated = db.Column(db.Boolean, default=False)
    confirmed = db.Column(db.Boolean, nullable=False, default=False)
   ## confirmed_on = db.Column(db.DateTime, nullable=True)

    def is_authenticated(self):
        """Return True if the user is authenticated."""
        return self.authenticated


class UserPosts(db.Model):
    __tablename__ = 'userPosts'
    id = db.Column(db.Integer, primary_key=True)
    post_date = db.Column(db.DateTime, default=datetime.utcnow)
    post = db.Column(db.String(10,000), nullable=False)

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


class Change(FlaskForm):
    email = StringField("Email", [validators.length(min=5, message="Length must be 5+"),
                                  validators.email(message="Must be email")])
    password = PasswordField('New Password', [validators.EqualTo('confirmation', message='Passwords must match'),
                                              validators.DataRequired("Required")])

    confirmation = PasswordField('Repeat Password', [validators.DataRequired("Required")])
    submit = SubmitField("Log in")
    def validate_email(self,email):
        email= Friends.query.filter_by(email=email.data).first()
        if email != None:
             raise ValidationError('That email is taken. Please choose another.')





def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])


def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(
            token,
            salt=app.config['SECURITY_PASSWORD_SALT'],
            max_age=expiration
        )
    except:
        return False
    return email

 ## @login_required


@app.route('/',methods=['GET','POST'])

def hi():
    form = InputLabels()

    if(form.validate_on_submit()):
        user =request.form['user']
        email = request.form['email']
        password = request.form['password']
        user1 = Friends(user=user, email=email,password=password,confirmed=False)
        user1.set_password(password)
        db.session.add(user1)
        db.session.commit()
     #   token = generate_confirmation_token(email)
      #  confirm_url = url_for(email, token=token, _external=True)
      #  print(confirm_url)
       # html = render_template('email.html', confirm_url=confirm_url)
       # subject = "Please confirm your email"
       #flas send_email(user.email, subject, html)

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
        user.authenticated = True
        login_user(user,remember=True)

        return redirect(url_for('profile',user= result))


    return render_template('Login.html', form = form)



@app.route('/Profile/<string:user>',methods=['GET','POST'])
@login_required
def profile(user):
    return render_template("Homepage.html",user = user)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('hi'))


@app.route("/Settings/<string:user>", methods=['GET', 'POST'])
def edit(user):

    form = Change()

    update1 = db.session.query(Friends).filter_by(user = user).first()

    if (form.validate_on_submit() and update1 is not None):



        update1.email =request.form['email']

        update1.password = request.form['password']
        db.session.merge(update1)
        db.session.commit()

        return redirect(url_for('sign'))
    return render_template('Edit.html', form=form ,user =user)





@app.route('/confirm/<token>')
@login_required
def confirm_email(token):
    try:
        email = confirm_token(token)
    except:
        flash('The confirmation link is invalid or has expired.', 'danger')
    user = Friends.query.filter_by(email=email).first_or_404()
    if user.confirmed:
        flash('Account already confirmed. Please login.', 'success')
    else:
        user.confirmed = True
        user.confirmed_on = datetime.datetime.now()
        db.session.add(user)
        db.session.commit()
        flash('You have confirmed your account. Thanks!', 'success')
    return redirect(url_for('main.home'))

@app.route('/ViewPosts', methods=['GET', 'POST'])
def view_posts():
    if request.method == "POST":
        usr_post = request.form['post']
        new_post = UserPosts(post=usr_post)
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for('view_posts'))

    else:
        all_posts = UserPosts.query.order_by(UserPosts.post_date)
        return render_template('ViewPosts.html', all_posts=all_posts)



def send_email(to, subject, template):
    msg = Message(
        subject,
        recipients=[to],
        html=template,
        sender=app.config['MAIL_DEFAULT_SENDER']
    )
    mail.send(msg)

if __name__ == '__main__':
    app.run()
