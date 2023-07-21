from datetime import date
from functools import wraps
from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date

from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, CreateUser, LoginForm
from flask_gravatar import Gravatar

# APP INIT
app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

# LOGIN ROUTINES
login_manager = LoginManager()
login_manager.init_app(app)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
Base = declarative_base()


# CONFIGURE TABLES

class BlogPost(db.Model, Base):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, ForeignKey('users.id'))
    author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author_id = relationship('User', back_populates='posts')


class User(db.Model, UserMixin, Base):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    posts = relationship('BlogPost', back_populates='author_id')


db.create_all()


def admin_only(function):
    @wraps(function)
    def deco_function(*args, **kwargs):
        if current_user.id != 2:
            flash("requires admin privileges")
            return abort(403)
        return function(*args, **kwargs)

    return deco_function


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = CreateUser()
    if request.method == 'POST':
        email_query = User.query.filter_by(email=form.email.data).first()
        if not email_query and form.password.data == form.confirm_password.data:
            encrypted_password = generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=8)
            new_user = User()
            new_user.email = form.email.data
            new_user.name = form.name.data
            new_user.password = encrypted_password

            db.session.add(new_user)
            db.session.commit()

            flash("successfully signed up")
            return redirect(url_for('get_all_posts', logged_in=current_user.is_authenticated))
        elif email_query:
            flash("email already in use; sign in instead")
            return redirect(url_for('login'))
        else:
            flash("un-matching passwords")
    return render_template("register.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    form = LoginForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            # check to see the user already exists on the database
            user_valid = User.query.filter_by(email=form.email.data).first()
            if user_valid and check_password_hash(user_valid.password, form.password.data):
                login_user(user_valid)
                return redirect(url_for('get_all_posts', logged_in=current_user.is_authenticated))

            # redirect to register page if the user email is invalid
            elif not user_valid:
                error = 'invalid email, sign up instead?'
                return redirect(url_for('register', error=error))
            else:
                error = 'invalid username or password'
                return render_template('login.html', error=error, form=form)
    return render_template("login.html", form=form, error=error)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts', logged_in=current_user.is_authenticated))


@app.route("/post/<int:post_id>")
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    return render_template("post.html", post=requested_post, logged_in=current_user.is_authenticated)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=['GET', 'POST'])
# @login_required
def add_new_post():
    form = CreatePostForm()
    print(current_user.is_authenticated)
    if (request.method == 'GET') and (not current_user.is_authenticated):
        flash('you need to login first')
        return redirect(url_for('login'))
    if form.validate_on_submit() and current_user.is_authenticated:
        if request.method == 'POST':
            new_post = BlogPost()

            new_post.title = form.title.data
            new_post.subtitle = form.subtitle.data
            new_post.body = form.body.data
            new_post.img_url = form.img_url.data
            new_post.author = current_user.name
            new_post.date = date.today().strftime("%B %d, %Y")
            # add the new post to the blogs database
            db.session.add(new_post)
            # append post to the post attribute in class user for the one-to-many relationship
            current_user.posts.append(new_post)
            # commit changes to the database to create the corresponding user id on blog post table
            db.session.commit()
            return redirect(url_for("get_all_posts", logged_in=True))
    return render_template("make-post.html", form=form, logged_in=current_user.is_authenticated)


@app.route("/edit-post/<int:post_id>", methods=['GET', 'POST'])
# @login_required
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )

    if (request.method == 'GET') and (not current_user.is_authenticated):
        flash('you need to log in first')
        return redirect(url_for('login'))
    if request.method == 'POST':
        if edit_form.validate_on_submit():
            post.title = edit_form.title.data
            post.subtitle = edit_form.subtitle.data
            post.img_url = edit_form.img_url.data
            post.author = current_user.name
            post.body = edit_form.body.data
            db.session.commit()
            return redirect(url_for("show_post", post_id=post.id, logged_in=current_user.is_authenticated))
    return render_template("make-post.html", form=edit_form, post_id=post.id, logged_in=current_user.is_authenticated)


@app.route("/delete/<int:post_id>")
@login_required
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts', logged_in=current_user.is_authenticated))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
