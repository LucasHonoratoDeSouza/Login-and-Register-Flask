from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
import bcrypt

app = Flask(__name__)
app.secret_key = "secrete-key"

# Configuração do banco de dados SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db?check_same_thread=False'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Evita avisos deprecados
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {"pool_pre_ping": True}


db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

@app.route("/")
def home():
    if "username" in session:
        return render_template("home.html", username=session["username"])
    return render_template("home.html")

@app.route("/login", methods=["POST", "GET"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            session["username"] = user.username
            return redirect(url_for("home"))
        return render_template("login.html", error="Credenciais inválidas")
    return render_template("login.html")

@app.route("/register", methods=["POST", "GET"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        # Verificar se o nome de usuário já está em uso
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return render_template("register.html", error="Nome de usuário já em uso")
        # Criptografar a senha antes de armazená-la no banco de dados
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        # Criar um novo usuário com a senha criptografada
        new_user = User(username=username, password=hashed_password.decode('utf-8'))
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect(url_for("home"))

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
