
from flask import Flask, render_template,  request, redirect, url_for, flash

##########################
#### importing flask extensions ####
##########################
from flask_login import LoginManager, login_user, current_user, login_required, logout_user
from flask_mail import Mail, Message
from threading import Thread
from itsdangerous import URLSafeTimedSerializer
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.hybrid import hybrid_method, hybrid_property
from flask_bcrypt import Bcrypt
from datetime import datetime
from forms import RegisterForm, LoginForm, ResetEmailForm,ResetPasswordForm
# from .forms import RegisterForm, LoginForm




#create the object of Flask
app  = Flask(__name__)
##########################
#### flask app configurations ####
##########################
app.config['SECRET_KEY'] = 'hardsecretkey'
#SqlAlchemy Database Configuration With Mysql
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:''@localhost/flasklogin'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
#Email related Configuration values
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'codesnnippetstests@gmail.com'
app.config['MAIL_PASSWORD'] = '@Codesnnippetstests2021'
app.config['MAIL_DEFAULT_SENDER'] = 'codesnnippetstests@gmail.com'


##########################
#### initialising flask extensions ####
##########################
db = SQLAlchemy(app)
mail = Mail(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
 

##########################
#### defining user model and its helper functions using sqlalchemy ####
##########################
 
class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    username = db.Column(db.String(255), unique=True, nullable=False)
    _password = db.Column(db.String(60), nullable=False)
    authenticated = db.Column(db.Boolean, default=False)
    email_confirmation_sent_on = db.Column(db.DateTime, nullable=True)
    email_confirmed = db.Column(db.Boolean, nullable=True, default=False)
    email_confirmed_on = db.Column(db.DateTime, nullable=True)

    def __init__(self, email,username, plaintext_password, email_confirmation_sent_on=None):
        self.email = email
        self.username = username
        self._password = plaintext_password
        
        self.authenticated = False
        self.email_confirmation_sent_on = email_confirmation_sent_on
        self.email_confirmed = False
        self.email_confirmed_on = None

    @hybrid_property
    def password(self):
        return self._password

    @hybrid_method
    def verify_original_pass(self, plaintext_password):
        return bcrypt.check_password_hash(self._password, plaintext_password)

    @property
    def is_authenticated(self):
        """Return True if the user is authenticated."""
        return self.authenticated

    @property
    def is_active(self):
        """Always True, as all users are active."""
        return True

    # @property
    # def is_anonymous(self):
    #     """Always False, as anonymous users aren't supported."""
    #     return False

    def get_id(self):
        """Return the email address to satisfy Flask-Login's requirements."""
        """Requires use of Python 3"""
        return str(self.id)



##########################
####mail sending,confirmation and password hashing helper functions ####
##########################

def flash_errors(form):
    for field, errors in form.errors.items():
        for error in errors:
            flash(u"Error in the %s field - %s" % (
                getattr(form, field).label.text,
                error
            ), 'info')


def send_async_email(msg):
    with app.app_context():
        mail.send(msg)


def send_email(subject, recipients, html_body):
    msg = Message(subject, recipients=recipients)
    msg.html = html_body
    thr = Thread(target=send_async_email, args=[msg])
    thr.start()


def send_confirmation_email(user_email):
    confirm_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

    confirm_url = url_for(
        'confirm_email',
        token=confirm_serializer.dumps(user_email, salt='email-confirmation-salt'),
        _external=True)

    html = render_template(
        'email_confirmation.html',
        confirm_url=confirm_url)

    send_email('Confirm Your Email Address', [user_email], html)


def send_password_reset_link(user_email):
    password_reset_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

    password_reset_url = url_for(
        'token_reset',
        token = password_reset_serializer.dumps(user_email, salt='password-reset-salt'),
        _external=True)

    html = render_template(
        'email_reset.html',
        password_reset_url=password_reset_url)

    send_email('Password Reset Requested', [user_email], html)




@login_manager.user_loader
def load_user(user_id):
    return User.query.filter(User.id == int(user_id)).first()
 

################
#### routes ####
################
@app.route('/')
def home():
    form = LoginForm(request.form)
    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST':
        if form.validate_on_submit():
            try:
            
                email = form.email.data
                username = form.username.data
                password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')

                new_user = User(email, username, password)
                new_user.authenticated = True
                db.session.add(new_user)
                db.session.commit()

                send_password_reset_link(new_user.email)
                flash('Thanks for registering!  Please check your email to confirm your email address.', 'success')
                return redirect(url_for('login'))

            except IntegrityError:
                db.session.rollback()
                flash('ERROR! Email ({}) already exists.'.format(form.email.data), 'error')
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm(request.form)
    if request.method == 'POST':
        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data).first()
            # if user is not None and user.is_correct_password(form.password.data):
            if user.email_confirmed==0:
                flash('Your acount is not activated! Please open your email inbox and click activation link we sent to activate it', 'info')
            elif user is not None and user.verify_original_pass(form.password.data):
                user.authenticated = True
                db.session.add(user)
                db.session.commit()
                login_user(user)
                flash('You are logged in now, {}'.format(current_user.username))
                return redirect(url_for('blog'))
            else:
                flash('ERROR! Incorrect login credentials.', 'error')
    return render_template('login.html', form=form)

# email confirmation and activationm route functions
@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        confirm_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        email = confirm_serializer.loads(token, salt='email-confirmation-salt', max_age=86400)
    except:
        flash('The confirmation link is invalid or has expired.', 'error')
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first()

    if user.email_confirmed:
        flash('Account already confirmed. Please login.', 'info')
    else:
        user.email_confirmed = True
        user.email_confirmed_on = datetime.now()
        db.session.add(user)
        db.session.commit()
        flash('Thank you for confirming your email address!', 'success')

    return redirect(url_for('blog'))

#reset_email password route
@app.route('/reset', methods=["GET", "POST"])
def reset_email():
    form = ResetEmailForm()
    if form.validate_on_submit():
        try:
            user = User.query.filter_by(email=form.email.data).first_or_404()
        except:
            flash('Invalid email address!', 'error')
            return render_template('password_reset.html', form=form)

        if user.email_confirmed:
            send_password_reset_link(user.email)
            flash('Please check your email for a password reset link.', 'success')
        else:
            flash('Your email address must be confirmed before attempting a password reset.', 'error')
        return redirect(url_for('login'))

    return render_template('password_reset.html', form=form)


@app.route('/reset/<token>', methods=["GET", "POST"])
def token_reset(token):
    try:
        password_reset_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        email = password_reset_serializer.loads(token, salt='password-reset-salt', max_age=3600)
    except:
        flash('The password reset link is invalid or has expired.', 'error')
        return redirect(url_for('login'))

    form = ResetPasswordForm()

    if form.validate_on_submit():
        try:
            user = User.query.filter_by(email=email).first_or_404()
        except:
            flash('Invalid email address!', 'error')
            return redirect(url_for('login'))

        user._password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        db.session.add(user)
        db.session.commit()
        flash('Your password has been updated!', 'success')
        return redirect(url_for('login'))

    return render_template('reset_token_pass.html',token=token, form=form)


@app.route('/blog')
@login_required
def blog():
    return render_template('blog.html')


@app.route('/logout')
@login_required
def logout():
    user = current_user
    user.authenticated = False
    db.session.add(user)
    db.session.commit()
    logout_user()
    flash('You are logged out,we hope you come back soon!', 'info')
    return redirect(url_for('login'))




#run flask app
if __name__ == "__main__":
    app.run(debug=True)