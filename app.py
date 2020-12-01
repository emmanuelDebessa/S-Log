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
from wtforms import ValidationError, TextAreaField
from flask_login import LoginManager
from flask_login import current_user, login_user
from flask_login import login_required
from flask_login import UserMixin
from itsdangerous import URLSafeTimedSerializer
from flask_login import logout_user
from flask_mail import Message,Mail
# from flask.ext.perm import Perm
import os
from wtforms.validators import length,email,email_validator,equal_to
app = Flask(__name__)
application = app

app.config['SECRET_KEY'] = 'hello123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///relationships.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

    # gmail authentication
app.config['MAIL_USERNAME'] = "jonlai0018"
app.config['MAIL_PASSWORD'] =  "Rh579782"

    # mail accounts
app.config['MAIL_DEFAULT_SENDER'] = "jonlai0018@gmail.com"


db = SQLAlchemy(app)
bootstrap = Bootstrap(app)
moment = Moment(app)
migrate = Migrate(app, db)
login = LoginManager(app)
login.login_view = 'sign'
mail = Mail(app)
# perm = Perm(app)

app.config['SECURITY_PASSWORD_SALT'] = 'emailpass'
app.config['SQLALCHEMY_BINDS'] = {
    'users': 'sqlite:///Users',
    'posts':  'sqlite:///posts'
}

# other imports as necessary
class UserPosts(db.Model):
    __bind_key__ = 'posts'
    id = db.Column(db.Integer, primary_key=True)
    post_date = db.Column(db.DateTime, default=datetime.utcnow)
    post_content = db.Column(db.String(10,000), nullable=False)
    post_title = db.Column(db.String(200), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('friends.id'))

class Friends(db.Model,UserMixin):
    __bind_key__ = 'users'
    image_file = db.Column(db.String(20), nullable=False, default='default_twitter.png')
    id = db.Column(db.INTEGER,primary_key=True)
    email = db.Column(db.String(200),nullable = False)
    user = db.Column(db.String(200),nullable = False)
    password = db.Column(db.String(200),nullable = False)
    password_hash = db.Column(db.String(200),nullable = False)
    authenticated = db.Column(db.Boolean, default=False)
    confirmed = db.Column(db.Boolean, nullable=False, default=False)
    posts = db.relationship('UserPosts', backref='author', lazy='dynamic')



   ## confirmed_on = db.Column(db.DateTime, nullable=True)

    def is_authenticated(self):
        """Return True if the user is authenticated."""
        return self.authenticated



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
    remember_me = BooleanField('Keep me logged in')

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
    submit = SubmitField("Submit")
    def validate_email(self,email):
        email= Friends.query.filter_by(email=email.data).first()
        if email != None:
             raise ValidationError('That email is taken. Please choose another.')

class Change_pass(FlaskForm):
    password = PasswordField('New Password', [validators.EqualTo('confirmation', message='Passwords must match'),
                                              validators.DataRequired("Required")])

    confirmation = PasswordField('Repeat Password', [validators.DataRequired("Required")])
    submit = SubmitField("Submit")


class Reset(FlaskForm):
    email = StringField("Email", [validators.length(min=5, message="Length must be 5+"),
                                  validators.email(message="Must be email")])

    submit = SubmitField("Submit")

class PostForm(FlaskForm):
    title = StringField('Title', validators.DataRequired("Required"))
    content = TextAreaField('Body', validators.DataRequired("Required"))
    submit = SubmitField('Post!')


def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])


def confirm_token(token, expiration=10000000000):
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
    
        token = generate_confirmation_token(email)
      
        confirm_url = url_for('confirm_email', token=token, _external=True)


        print(token)
        html = render_template('activate.html', confirm_url=confirm_url)
        subject = "Please confirm your email"
        send_email(email, subject, html)
        flash('A confirmation email has been sent via email.', 'success')
        db.session.add(user1)
        db.session.commit()

        return redirect(url_for("sign"))








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
            print("hello")

            flash("Invalid Username or Password")
            return render_template('Login.html', form=form)
        if user.confirmed is False:
            flash("Confirm Email")
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


@app.route("/Password/<string:user>", methods=['GET', 'POST'])
@login_required
def edit(user):
    form = Change()

    user_to_update = Friends.query.filter_by(user = user).first_or_404()





    if(form.validate_on_submit()):

        if(request.form['email'] != user_to_update.email):
            flash("Wrong Email")
        else:


            user_to_update.password = request.form['password']
            user_to_update.set_password(request.form['password'])
            db.session.add(user_to_update)
            db.session.commit()

            flash("Password Change Succesfully")


    return render_template('Edit.html', form=form ,user =user)



@app.route("/Email/<string:user>", methods=['GET', 'POST'])
@login_required
def Email_change(user):
    form = Change()

    user_to_update = Friends.query.filter_by(user = user).first_or_404()




    if(form.validate_on_submit()):



            user_to_update.email = request.form['email']
            user_to_update.confirmed= False
            token = generate_confirmation_token(request.form['email'])
            confirm_url = url_for('confirm_email', token=token, _external=True)


            html = render_template('activate.html', confirm_url=confirm_url)
            subject = "Please confirm your email"
            send_email(request.form['email'], subject, html)
            flash('A confirmation email has been sent via email. You need to confirm your email before being able to login', 'success')
            logout()



            db.session.add(user_to_update)
            db.session.commit()




    return render_template('Email_Update.html', form=form ,user =user)





@app.route("/Reset/", methods=['GET', 'POST'])

def Recover():
    form = Reset()






    if(form.validate_on_submit() ):
        email= request.form['email']
        user_to_update = Friends.query.filter_by(email=email).first()
        if(user_to_update is not None):

            token = generate_confirmation_token(email)
            confirm_url = url_for('confirm_pass', token=token, _external=True)
            html = render_template('activate.html', confirm_url=confirm_url)
            subject = "Password Reset"
            send_email(request.form['email'], subject, html)
            flash("Done")
        else:
            flash("No account associated with this email")
    return render_template('Reset_password.html', form=form)













@app.route('/confirm_pass/<token>' ,methods=['GET', 'POST'])

def confirm_pass(token):
    form = Change_pass()

    try:
        email = confirm_token(token)
    except:
        flash('The confirmation link is invalid or has expired.', 'danger')
    user = Friends.query.filter_by(email=email).first_or_404()
    if (form.validate_on_submit()):
        password = request.form['password']
        user.password=password
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash("done")
    else:
        flash("broken")



    return render_template('Recover_pass.html',form = form,token= token)












@app.route('/confirm/<token>')

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
        db.session.add(user)
        db.session.commit()
        flash('You have confirmed your account. Thanks!', 'success')
    return redirect(url_for("sign"))


def send_email(to, subject, template):
    msg = Message(
        subject,
        recipients=[to],
        html=template,
        sender=app.config['MAIL_DEFAULT_SENDER']
    )
    mail.send(msg)

def get_post(id, check_author=True):
    post = UserPosts.query.filter_by(id=id).first()
    return post

# @perm.current_user_loader(lambda: current_user)
@app.route('/updatePost/<int:id>/', methods=['GET','POST'])
@login_required
def update(id):
    updated_post = get_post(id)
    updateform = PostForm()
    if updateform.validate_on_submit():
        updated_post.post_title = updateform.title.data
        updated_post.post_content = updateform.content.data
        db.session.commit()
        flash("Your post has been updated!")
        return redirect(url_for('view_posts'))
    elif request.method == 'GET':
        form.title.data = updated_post.post_title
        form.content.data = updated_post.post_content
    return render_template('ViewPosts.html', updateform=updateform)

@app.route('/deletePost/<int:id>/', methods=['GET','POST'])
@login_required
def delete(id):
    deleted = get_post(id)
    db.session.delete(deleted)
    db.session.commit()
    return redirect(url_for('view_posts'))

@app.route('/ViewPosts', methods=['GET', 'POST'])
def view_posts():
    if request.method == "POST":
        usr_post = request.form['post_content']
        usr_title = request.form['post_title']
        new_post = UserPosts(post_content=usr_post,post_title=usr_title, author=current_user)
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for('view_posts'))

    else:
        all_posts = UserPosts.query.order_by(UserPosts.post_date)

        return render_template('ViewPosts.html', all_posts=all_posts)


@app.route('/Account')
@login_required
def account():
    image_file = url_for('static', filename='profile_images/' + current_user.image_file)
    return render_template('account.html',title = "Account",image = image_file)


if __name__ == '__main__':
    app.run()
