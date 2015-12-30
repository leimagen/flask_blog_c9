from flask_blog import app
from flask_blog import db, uploaded_images
from flask import render_template, redirect, url_for, session, request, flash
from author.form import RegisterForm, LoginForm
from author.models import Author
from author.decorators import login_required
import bcrypt

@app.route('/login', methods=('GET', 'POST'))
def login():
    form = LoginForm()
    error=None
    
    if request.method == "GET" and request.args.get('next'):
        session['next'] = request.args.get('next', None)
        
    if form.validate_on_submit():
        author = Author.query.filter_by(
            username= form.username.data
            ).first()
        if author:
            if bcrypt.hashpw(form.password.data, author.password) == author.password:
                session['username'] = form.username.data
                session['is_author'] = author.is_author
                flash("User %s logged in" % form.username.data)
                if 'next' in session:
                    next= session.get('next')
                    session.pop('next')
                    return redirect(next)
                else:
                    return redirect(url_for('admin'))
            else:
                error = "Incorrect username and password"
        else:
            error = "Incorrect username and password"
    return render_template('author/login.html', form=form, error=error)
    
@app.route('/register', methods=('GET', 'POST'))
def register():
    form = RegisterForm()
    error = None
    if form.validate_on_submit():
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(form.password.data, salt)
        author = Author(
            form.fullname.data,
            form.email.data,
            form.username.data,
            hashed_password,
            form.is_author.data
            )
        db.session.add(author)
        db.session.flush()
        
        if author.id:
            db.session.commit()
            flash("User created successfully!")
            return redirect(url_for('success'))
        else: 
            db.session.rollback()
            error = "Error creating user"
    return render_template('author/register.html', form=form)
    
@app.route('/success')
def success():
    return redirect(url_for('login'))
    
@app.route('/logout')
def logout():
    session.pop('username')
    session.pop('is_author')
    flash("User logged out")
    return redirect(url_for('index'))
