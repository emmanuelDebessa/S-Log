import os
from flask import Flask, render_template, session, redirect, url_for, request
from flask_bootstrap import Bootstrap
from flask_moment import Moment
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime

app = Flask(__name__)
bootstrap = Bootstrap(app)
basedir = os.path.abspath(os.path.dirname(__file__))

app.config['SQLALCHEMY_DATABASE_URI'] =\
    'sqlite:///' + os.path.join(basedir, 'data.sqlite')
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class UserPosts(db.Model):
    __tablename__ = 'userPosts'
    id = db.Column(db.Integer, primary_key=True)
    post_date = db.Column(db.DateTime, default=datetime.utcnow)
    post = db.Column(db.String(10,000), nullable=False)

    def __repr__(self):
        return '<Post %r>' % self.post

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
