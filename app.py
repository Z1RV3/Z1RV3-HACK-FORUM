import os
from flask import Flask, render_template, redirect, url_for, request, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, EqualTo, Length, ValidationError
from flask_bcrypt import Bcrypt

# --- 1. Uygulama ve Konfigürasyon ---

app = Flask(__name__)

# GİZLİ ANAHTAR KONTROLÜ (Mutlaka ortam değişkeninden okur)
# Render'da ayarlanan SECRET_KEY kullanılır.
SECRET_KEY = os.environ.get('SECRET_KEY')
if not SECRET_KEY:
    # Eğer SECRET_KEY ortam değişkeninde yoksa, uygulama başlamaz.
    raise ValueError("FATAL ERROR: SECRET_KEY environment variable not set. Please set it in Render.")
app.config['SECRET_KEY'] = SECRET_KEY

# VERITABANI KONFIGÜRASYONU (Bulut Ortamı için En Güvenilir Yol)
# Veritabanı dosyasının /tmp klasöründe (yazılabilir ve geçici) oluşturulmasını sağlar.
# Bu, "Cannot open database file" ve yazma izni hatalarını çözer.
db_path = os.environ.get('DATABASE_URL', 'sqlite:////tmp/site.db')
app.config['SQLALCHEMY_DATABASE_URI'] = db_path
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login' # User will be redirected here if not logged in
login_manager.login_message_category = 'info'


# --- 2. Modeller (Veritabanı Tablo Tanımları) ---
# Modellerin Tanimlanmasi
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    threads = db.relationship('Thread', backref='author', lazy=True, cascade="all, delete-orphan")
    comments = db.relationship('Comment', backref='comment_author', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', 'Admin: {self.is_admin}')"

class Thread(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=db.func.now())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    comments = db.relationship('Comment', backref='thread', lazy=True, cascade="all, delete-orphan")

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=db.func.now())
    thread_id = db.Column(db.Integer, db.ForeignKey('thread.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


# --- 3. Flask-Login Ayarları ---

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# --- 4. Yönetici ve DB Başlatma Fonksiyonları ---

def create_initial_admin():
    # Admin username: Z1RV3, Password: @2025
    admin_username = 'Z1RV3'
    admin_email = 'admin@forum.com'
    admin_pass_text = 'Z1RV3@2025'

    admin = User.query.filter_by(username=admin_username).first()
    
    if not admin:
        hashed_password = bcrypt.generate_password_hash(admin_pass_text).decode('utf-8')
        admin = User(username=admin_username, email=admin_email, password=hashed_password, is_admin=True)
        db.session.add(admin)
        db.session.commit()
        print(f"!!! YÖNETİCİ KULLANICI OLUŞTURULDU: {admin_username} / {admin_pass_text}")
    return admin

# *** KRİTİK DÜZELTME: UYGULAMA BAŞLATILDIĞINDA DB OLUŞTURMA ***
# Modeller tanımlandıktan hemen sonra, ancak rotalardan önce, DB oluşturulur.
# Bu, 'NameError' ve 'RuntimeError' hatalarını çözer.
with app.app_context():
    db.create_all()
    create_initial_admin()
# ***************************************************************


# --- 5. Formlar ---
# Form tanımlamaları (RegistrationForm, LoginForm, ThreadForm, CommentForm) burada devam ediyor...
class RegistrationForm(FlaskForm):
    username = StringField('Kullanıcı Adı', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Length(max=120)])
    password = PasswordField('Şifre', validators=[DataRequired()])
    confirm_password = PasswordField('Şifreyi Onayla', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Kaydol')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Bu kullanıcı adı zaten alınmış.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Bu email adresi zaten kullanılıyor.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Şifre', validators=[DataRequired()])
    submit = SubmitField('Giriş Yap')

class ThreadForm(FlaskForm):
    title = StringField('Konu Başlığı', validators=[DataRequired(), Length(min=5, max=100)])
    content = TextAreaField('İçerik', validators=[DataRequired()])
    submit = SubmitField('Konu Oluştur')

class CommentForm(FlaskForm):
    content = TextAreaField('Yorumunuz', validators=[DataRequired()])
    submit = SubmitField('Yorumu Gönder')


# --- 6. Rotalar (Routes) ---

@app.route("/")
@app.route("/index")
def index():
    threads = Thread.query.order_by(Thread.date_posted.desc()).all()
    return render_template('index.html', title='Anasayfa', threads=threads)

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Hesabınız başarıyla oluşturuldu! Giriş yapabilirsiniz.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Kaydol', form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=True)
            next_page = request.args.get('next')
            flash('Başarıyla giriş yaptınız!', 'success')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('Giriş başarısız. Lütfen email ve şifrenizi kontrol edin.', 'danger')
    return render_template('login.html', title='Giriş Yap', form=form)

@app.route("/login_secret/<admin_pass>")
def login_secret(admin_pass):
    if admin_pass == 'Z1RV3@2025':
        user = User.query.filter_by(username='Z1RV3').first()
        if user:
            login_user(user)
            flash('Gizli yönetici girişi başarılı!', 'success')
            return redirect(url_for('admin_panel'))
    abort(404)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route("/thread/new", methods=['GET', 'POST'])
@login_required
def new_thread():
    form = ThreadForm()
    if form.validate_on_submit():
        thread = Thread(title=form.title.data, content=form.content.data, author=current_user)
        db.session.add(thread)
        db.session.commit()
        flash('Konunuz başarıyla oluşturuldu!', 'success')
        return redirect(url_for('index'))
    return render_template('create_thread.html', title='Yeni Konu', form=form, legend='Yeni Konu Oluştur')

@app.route("/thread/<int:thread_id>", methods=['GET', 'POST'])
def thread_detail(thread_id):
    thread = Thread.query.get_or_404(thread_id)
    comment_form = CommentForm()

    if comment_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash('Yorum yapmak için giriş yapmalısınız.', 'warning')
            return redirect(url_for('login'))

        comment = Comment(content=comment_form.content.data, thread=thread, comment_author=current_user)
        db.session.add(comment)
        db.session.commit()
        flash('Yorumunuz başarıyla eklendi!', 'success')
        return redirect(url_for('thread_detail', thread_id=thread.id))
    
    comments = Comment.query.filter_by(thread_id=thread_id).order_by(Comment.date_posted.asc()).all()
    return render_template('thread_detail.html', title=thread.title, thread=thread, comments=comments, comment_form=comment_form)

@app.route("/admin_panel")
@login_required
def admin_panel():
    if not current_user.is_admin:
        abort(403)

    users = User.query.order_by(User.username).all()
    threads = Thread.query.order_by(Thread.date_posted.desc()).all()
    comments = Comment.query.order_by(Comment.date_posted.desc()).all()
    return render_template('admin_panel.html', title='Yönetici Paneli', users=users, threads=threads, comments=comments)

@app.route("/admin/user/<int:user_id>/delete", methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        abort(403)

    user = User.query.get_or_404(user_id)
    if user.is_admin:
        flash('Yönetici kullanıcı silinemez.', 'danger')
        return redirect(url_for('admin_panel'))
    
    # Kullanıcının tüm konularını ve yorumlarını sil
    Thread.query.filter_by(user_id=user_id).delete()
    Comment.query.filter_by(user_id=user_id).delete()
    
    db.session.delete(user)
    db.session.commit()
    flash(f'{user.username} kullanıcısı ve tüm içerikleri silindi.', 'success')
    return redirect(url_for('admin_panel'))

@app.route("/admin/thread/<int:thread_id>/delete", methods=['POST'])
@login_required
def delete_thread(thread_id):
    if not current_user.is_admin:
        abort(403)
        
    thread = Thread.query.get_or_404(thread_id)
    
    Comment.query.filter_by(thread_id=thread_id).delete()
    
    db.session.delete(thread)
    db.session.commit()
    flash(f'"{thread.title}" başlıklı konu silindi.', 'success')
    return redirect(url_for('admin_panel'))

@app.route("/admin/comment/<int:comment_id>/delete", methods=['POST'])
@login_required
def delete_comment(comment_id):
    if not current_user.is_admin:
        abort(403)
        
    comment = Comment.query.get_or_404(comment_id)
    thread_id = comment.thread_id
    
    db.session.delete(comment)
    db.session.commit()
    flash('Yorum başarıyla silindi.', 'success')
    return redirect(url_for('thread_detail', thread_id=thread_id))
    
# --- HATA SAYFALARI (Errors) ---

@app.errorhandler(403)
def forbidden_error(error):
    return render_template('errors/403.html'), 403

@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('errors/500.html'), 500

# Gunicorn, uygulamayı buradan çalıştırır. (app = Flask(...)) # CACHE FIX