class UserPosts(db.Model):
    __bind_key__ = 'posts'
    __tablename__ = 'posts'
    id = db.Column(db.Integer, primary_key=True)
    post_date = db.Column(db.DateTime, default=datetime.utcnow)
    post_content = db.Column(db.String(10,000), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))


class Friends(db.Model,UserMixin):
    __bind_key__ = 'users'
    __tablename__ = 'posts'
    image_file = db.Column(db.String(20), nullable=False, default='default_twitter.png')
    id = db.Column(db.INTEGER,primary_key=True)
    email = db.Column(db.String(200),nullable = False)
    user = db.Column(db.String(200),nullable = False)
    password = db.Column(db.String(200),nullable = False)
    password_hash = db.Column(db.String(200),nullable = False)
    authenticated = db.Column(db.Boolean, default=False)
    confirmed = db.Column(db.Boolean, nullable=False, default=False)
    posts = db.relationship('UserPosts', backref='author', lazy='dynamic')
    
    
@app.route('/ViewPosts', methods=['GET', 'POST'])
def view_posts():
    if request.method == "POST":
        usr_post = request.form['post_content']
        post = UserPosts(post_content=usr_post.body.data,
                    author=current_user._get_current_object())
        new_post = UserPosts(post_content=usr_post)
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for('view_posts'))

    else:
        all_posts = UserPosts.query.order_by(UserPosts.post_date)

        return render_template('ViewPosts.html', all_posts=all_posts)
        
        
