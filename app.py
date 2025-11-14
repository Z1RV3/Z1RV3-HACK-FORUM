import os
from flask import Flask, render_template, redirect, url_for, request, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_wtf import FlaskForm
from flask_bcrypt import Bcrypt
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from datetime import datetime

# --- APPLICATION CONFIGURATION ---
app = Flask(__name__)

# Render Environment Variable Check: Ensures SECRET_KEY is defined.
SECRET_KEY = os.environ.get('SECRET_KEY')
if not SECRET_KEY:
    # Bu hata, Render Environment sekmesinde SECRET_KEY ayarlanmadıysa ortaya çıkar.
    raise ValueError("FATAL ERROR: SECRET_KEY environment variable not set. Please set it in Render.")
app.config['SECRET_KEY'] = SECRET_KEY

# Database Path Definition: Uses the /tmp/ directory which is writable on Render for SQLite.
db_path = os.environ.get('DATABASE_URL', 'sqlite:////tmp/site.db')
app.config['SQLALCHEMY_DATABASE_URI'] = db_path
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login' 
login_manager.login_message_category = 'info'
login_manager.login_message = "Bu sayfaya erişmek için giriş yapmalısınız." # User visible message

# --- MODELS ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    threads = db.relationship('Thread', backref='author', lazy=True)
    posts = db.relationship('Post', backref='author', lazy=True)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"

class Thread(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    # Using datetime.utcnow for timezone-aware storage (recommended over func.now() in some setups)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow) 
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    # Cascade ensures posts are deleted when the thread is deleted
    posts = db.relationship('Post', backref='thread', lazy=True, cascade="all, delete-orphan") 

    def __repr__(self):
        return f"Thread('{self.title}', '{self.date_posted}')"

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    thread_id = db.Column(db.Integer, db.ForeignKey('thread.id'), nullable=False)

    def __repr__(self):
        return f"Post('{self.content[:20]}...', '{self.date_posted}')"

# --- FORMS ---
class RegistrationForm(FlaskForm):
    username = StringField('Kullanıcı Adı', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Şifre', validators=[DataRequired()])
    confirm_password = PasswordField('Şifreyi Onayla', validators=[DataRequired(), EqualTo('password', message='Şifreler eşleşmiyor.')])
    submit = SubmitField('Kayıt Ol')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Bu kullanıcı adı zaten alınmış.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Bu e-posta adresi zaten kayıtlı.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Şifre', validators=[DataRequired()])
    submit = SubmitField('Giriş Yap')

class ThreadForm(FlaskForm):
    title = StringField('Başlık', validators=[DataRequired(), Length(min=5, max=100)])
    content = TextAreaField('İçerik', validators=[DataRequired()])
    submit = SubmitField('Konu Aç')

class PostForm(FlaskForm):
    content = TextAreaField('Cevap', validators=[DataRequired()])
    submit = SubmitField('Cevapla')

# --- HELPER FUNCTIONS ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def create_initial_admin():
    """Veritabanında admin hesabı yoksa varsayılan admini oluşturur."""
    if User.query.filter_by(is_admin=True).first() is None:
        if User.query.filter_by(username='admin').first() is None:
            hashed_password = bcrypt.generate_password_hash('admin123').decode('utf-8')
            admin_user = User(username='admin', email='admin@forum.com', password=hashed_password, is_admin=True)
            db.session.add(admin_user)
            db.session.commit()
            print("!!! Varsayılan admin hesabı oluşturuldu: admin/admin123 !!!")
        else:
             print("!!! Admin hesabı zaten mevcut (admin@forum.com) !!!")
    else:
        print("!!! En az bir admin hesabı mevcut, yeni admin oluşturulmadı !!!")


# !!! CRITICAL FIX FOR RENDER DEPLOYMENT: db.create_all() and admin creation are done here !!!
with app.app_context():
    try:
        db.create_all() # Create tables (if they do not exist)
        create_initial_admin() # Create admin user (if not already existing)
        print("Veritabanı başlatma işlemi tamamlandı.")
    except Exception as e:
        print(f"HATA: Veritabanı başlatılırken bir hata oluştu: {e}")
# !!! FIX ENDS HERE !!!


# --- RUTES (ROUTES) ---

@app.route("/")
@app.route("/index")
# CRITICAL FIX: Changed function name from 'index' to 'home' to resolve 'home' BuildError in templates.
def home():
    # Fetch all threads, ordered by newest first
    threads = Thread.query.order_by(Thread.date_posted.desc()).all()
    return render_template('index.html', title='Anasayfa', threads=threads)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home')) # FIX: Use 'home'
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            flash(f'Giriş başarılı, hoş geldiniz {user.username}!', 'success')
            return redirect(next_page or url_for('home')) # FIX: Use 'home'
        else:
            flash('Giriş başarısız. Lütfen e-posta ve şifrenizi kontrol edin.', 'danger')
    return render_template('login.html', title='Giriş Yap', form=form)

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home')) # FIX: Use 'home'
    
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Hesabınız oluşturuldu! Şimdi giriş yapabilirsiniz.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Kayıt Ol', form=form)

@app.route("/logout")
def logout():
    logout_user()
    flash('Başarıyla çıkış yaptınız.', 'success')
    return redirect(url_for('home')) # FIX: Use 'home'

@app.route("/thread/new", methods=['GET', 'POST'])
@login_required
def new_thread():
    form = ThreadForm()
    if form.validate_on_submit():
        thread = Thread(title=form.title.data, content=form.content.data, author=current_user)
        db.session.add(thread)
        db.session.commit()
        return redirect(url_for('thread_detail', thread_id=thread.id))
    return render_template('create_thread.html', title='Yeni Konu', form=form)

@app.route("/thread/<int:thread_id>", methods=['GET', 'POST'])
def thread_detail(thread_id):
    thread = Thread.query.get_or_404(thread_id)
    form = PostForm()
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("Cevap yazmak için giriş yapmalısınız.", 'warning')
            return redirect(url_for('login', next=request.url))
            
        post = Post(content=form.content.data, thread=thread, author=current_user)
        db.session.add(post)
        db.session.commit()
        flash('Cevabınız başarıyla eklendi!', 'success')
        return redirect(url_for('thread_detail', thread_id=thread.id))
    
    posts = Post.query.filter_by(thread_id=thread.id).order_by(Post.date_posted.asc()).all()
    
    return render_template('thread_detail.html', title=thread.title, thread=thread, posts=posts, form=form)

@app.route("/thread/<int:thread_id>/delete", methods=['POST'])
@login_required
def delete_thread(thread_id):
    thread = Thread.query.get_or_404(thread_id)
    if thread.author != current_user and not current_user.is_admin:
        abort(403) # Forbidden access
    
    db.session.delete(thread)
    db.session.commit()
    flash('Konu başarıyla silindi.', 'success')
    return redirect(url_for('home')) # FIX: Use 'home'

@app.route("/post/<int:post_id>/delete", methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    thread_id = post.thread.id
    if post.author != current_user and not current_user.is_admin:
        abort(403) # Forbidden access
        
    db.session.delete(post)
    db.session.commit()
    flash('Cevap başarıyla silindi.', 'success')
    return redirect(url_for('thread_detail', thread_id=thread_id))

# Admin panel (Optional)
@app.route("/admin_panel")
@login_required
def admin_panel():
    if not current_user.is_admin:
        abort(403)
    users = User.query.all()
    threads = Thread.query.all()
    posts = Post.query.all()
    return render_template('admin_panel.html', title='Admin Paneli', users=users, threads=threads, posts=posts)


# --- ERROR HANDLING (Requires templates/errors/404.html and 403.html) ---

@app.errorhandler(404)
def error_404(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(403)
def error_403(error):
    return render_template('errors/403.html'), 403
    
# --- APPLICATION START (For Local Testing Only - Not executed by Gunicorn) ---
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
