from flask import Flask, request, render_template, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
import csv
from io import StringIO
from flask import Response
from cryptography.fernet import Fernet
import bcrypt
import random
from flask_mail import Mail, Message  # Pour envoyer des emails pour 2FA
from functools import wraps
from datetime import datetime, timedelta

app = Flask(__name__)

# Configuration de la base de données SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///gestionnaire_mdp.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'super_secret_key'  # Remplace par une vraie clé secrète

db = SQLAlchemy(app)

# Configuration de Flask-Mail pour l'envoi d'emails
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'cypherprimeinc@gmail.com'  # Ton adresse email
app.config['MAIL_PASSWORD'] = 'oniv sizh ntzs ufsa'  # Mot de passe d'application
app.config['MAIL_DEFAULT_SENDER'] = 'cypherprimeinc@gmail.com'
mail = Mail(app)

# Générer ou charger une clé AES pour chiffrer et déchiffrer les mots de passe
try:
    with open("secret.key", "rb") as key_file:
        key = key_file.read()
except FileNotFoundError:
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

cipher_suite = Fernet(key)

# Exemple de fonction pour chiffrer un mot de passe
def encrypt_password(password):
    return cipher_suite.encrypt(password.encode())

# Exemple de fonction pour déchiffrer un mot de passe
def decrypt_password(encrypted_password):
    try:
        return cipher_suite.decrypt(encrypted_password).decode()
    except Exception as e:
        return f"Erreur lors du déchiffrement : {e}"

# Modèle utilisateur avec suppression en cascade des mots de passe
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.LargeBinary, nullable=False)
    is_admin = db.Column(db.Boolean, default=False)  # Nouveau champ pour l'administrateur
    passwords = db.relationship('Password', backref='user', lazy=True, cascade="all, delete-orphan")

# Modèle des mots de passe
class Password(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    website = db.Column(db.String(150), nullable=False)
    username = db.Column(db.String(150), nullable=False)
    password = db.Column(db.LargeBinary, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Créer la base de données avec un superuser
with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        hashed_password = bcrypt.hashpw("adminpass".encode('utf-8'), bcrypt.gensalt())
        admin_user = User(username='admin', email='kbrahima075@gmail.com', password=hashed_password, is_admin=True)
        db.session.add(admin_user)
        db.session.commit()

# Décorateur pour vérifier si l'utilisateur est connecté
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Décorateur pour vérifier si l'utilisateur est admin
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        user = User.query.filter_by(username=session['username']).first()
        if not user.is_admin:
            flash("Accès réservé aux administrateurs.", "danger")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Vérifier si la 2FA doit être requise (ici après 1 semaine)
def needs_2fa():
    last_2fa = session.get('last_2fa')
    if last_2fa:
        last_2fa_time = datetime.strptime(last_2fa, '%Y-%m-%d %H:%M:%S')
        if datetime.now() - last_2fa_time < timedelta(weeks=1):  # Ajuste le délai si nécessaire
            return False
    return True

# Route d'administration
@app.route('/admin')
@admin_required
def admin_dashboard():
    users = User.query.all()  # L'administrateur peut voir tous les utilisateurs
    return render_template('admin_dashboard.html', users=users)

# Route pour le formulaire d'inscription
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # Vérification si l'utilisateur ou l'email existe déjà
        existing_user = User.query.filter_by(username=username).first()
        existing_email = User.query.filter_by(email=email).first()

        if existing_user:
            flash("Erreur : L'utilisateur avec ce nom existe déjà.", "danger")
            return redirect(url_for('signup'))

        if existing_email:
            flash("Erreur : Un compte avec cet email existe déjà.", "danger")
            return redirect(url_for('signup'))

        # Hacher le mot de passe
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Créer un nouvel utilisateur avec l'email et le mot de passe haché
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash("Inscription réussie ! Connectez-vous maintenant.", "success")
        return redirect(url_for('login'))

    return render_template('signup.html')

# Route pour la vérification 2FA
@app.route('/verify_2fa', methods=['GET', 'POST'])
def verify_2fa():
    if request.method == 'POST':
        code = request.form['code']

        # Vérifier si le code correspond à celui généré
        if 'verification_code' in session and str(session['verification_code']) == code:
            session['last_2fa'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')  # Enregistrer la dernière vérification 2FA
            flash("Vérification réussie !", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Code de vérification incorrect.", "danger")
            return redirect(url_for('verify_2fa'))

    return render_template('a2f.html')

# Route pour la connexion
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and bcrypt.checkpw(password.encode('utf-8'), user.password):
            session['username'] = user.username

            if not needs_2fa():
                # Rediriger directement vers le tableau de bord si la 2FA n'est pas nécessaire
                return redirect(url_for('admin_dashboard' if user.is_admin else 'dashboard'))

            # Générer un code de vérification à 6 chiffres
            verification_code = random.randint(100000, 999999)
            session['verification_code'] = verification_code

            # Envoyer l'email avec le code de vérification
            msg = Message('Votre code de vérification', recipients=[user.email])
            msg.body = f"Voici votre code de vérification : {verification_code}"
            mail.send(msg)

            return redirect(url_for('verify_2fa'))

        else:
            flash("Nom d'utilisateur ou mot de passe incorrect.", "danger")
            return redirect(url_for('login'))

    return render_template('login.html')

# Route pour supprimer un compte utilisateur (avec suppression en cascade des mots de passe)
@app.route('/delete_user/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash(f"Compte utilisateur '{user.username}' supprimé avec succès.", "success")
    else:
        flash("Utilisateur introuvable.", "danger")
    return redirect(url_for('admin_dashboard'))

# Tableau de bord pour les utilisateurs connectés
@app.route('/dashboard')
@login_required
def dashboard():
    user = User.query.filter_by(username=session['username']).first()
    passwords = user.passwords
    # Déchiffrer les mots de passe avant de les afficher
    for password in passwords:
        password.password = decrypt_password(password.password)
    return render_template('dashboard.html', passwords=passwords)

# Route pour ajouter un mot de passe
@app.route('/add_password', methods=['GET', 'POST'])
@login_required
def add_password():
    if request.method == 'POST':
        website = request.form['website']
        username = request.form['username']
        password = request.form['password']

        # Chiffrer le mot de passe avant de l'enregistrer
        encrypted_password = encrypt_password(password)

        user = User.query.filter_by(username=session['username']).first()
        new_password = Password(website=website, username=username, password=encrypted_password, user=user)

        db.session.add(new_password)
        db.session.commit()

        flash("Mot de passe ajouté avec succès.", "success")
        return redirect(url_for('dashboard'))

    return render_template('password.html')

# Route pour supprimer un mot de passe
@app.route('/delete_password/<int:password_id>', methods=['POST'])
@login_required
def delete_password(password_id):
    password = Password.query.get(password_id)
    if password and password.user.username == session['username']:
        db.session.delete(password)
        db.session.commit()

    flash("Mot de passe supprimé avec succès.", "success")
    return redirect(url_for('dashboard'))

# Route pour modifier un mot de passe
@app.route('/edit_password/<int:password_id>', methods=['GET', 'POST'])
@login_required
def edit_password(password_id):
    password = Password.query.get(password_id)

    if password and password.user.username == session['username']:
        if request.method == 'POST':
            new_password = request.form['password']
            password.password = encrypt_password(new_password)

            db.session.commit()
            flash("Mot de passe modifié avec succès.", "success")
            return redirect(url_for('dashboard'))

        return render_template('edit_password.html', password=password)

    return redirect(url_for('dashboard'))

# Route pour exporter les mots de passe en CSV
@app.route('/export_passwords')
@login_required
def export_passwords():
    user = User.query.filter_by(username=session['username']).first()
    passwords = user.passwords

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['Site Web', 'Nom d\'utilisateur', 'Mot de passe'])

    for password in passwords:
        writer.writerow([password.website, password.username, decrypt_password(password.password)])

    output.seek(0)
    return Response(output, mimetype="text/csv", headers={"Content-Disposition": "attachment;filename=passwords.csv"})

# Déconnexion
@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('last_2fa', None)  # Supprimer l'enregistrement de la 2FA
    flash("Déconnexion réussie.", "success")
    return redirect(url_for('home'))  # 'home' au lieu de 'Home'

# Page d'accueil
@app.route('/')
def home():
    return render_template('Home.html')

if __name__ == '__main__':
    app.run(debug=True)
