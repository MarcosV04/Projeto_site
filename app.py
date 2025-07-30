from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin

app = Flask(__name__)
app.config['SECRET_KEY'] = 'segredo-super-seguro'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Modelo de usuário
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

from datetime import datetime

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
@login_required
def home():
    return render_template('index.html', username=current_user.username)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and bcrypt.check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Usuário ou senha inválidos.')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        hashed_pw = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        new_user = User(username=request.form['username'], password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        flash('Conta criada com sucesso! Faça login.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/chat', methods=['GET', 'POST'])
@login_required
def chat():
    if request.method == 'POST':
        content = request.form['message']
        if content:
            msg = Message(sender_id=current_user.id, content=content)
            db.session.add(msg)
            db.session.commit()
    messages = Message.query.order_by(Message.timestamp.asc()).all()
    return render_template('chat.html', messages=messages, current_user=current_user)

from datetime import datetime, date
from flask_login import login_required

@app.route('/calendario')
@login_required
def calendario():
    data_inicio = date(2021, 10, 17)  # Substitua pela data real de vocês
    hoje = date.today()
    dias_juntos = (hoje - data_inicio).days

    # Proximo mesversário
    if hoje.day < data_inicio.day:
        proximo_mes = hoje.month
        proximo_ano = hoje.year
    else:
        proximo_mes = hoje.month + 1
        proximo_ano = hoje.year
        if proximo_mes > 12:
            proximo_mes = 1
            proximo_ano += 1

    try:
        proximo_mesversario = date(proximo_ano, proximo_mes, data_inicio.day)
    except ValueError:
        # caso o mês não tenha esse dia (ex: 31/02), coloca último dia do mês
        from calendar import monthrange
        proximo_dia = monthrange(proximo_ano, proximo_mes)[1]
        proximo_mesversario = date(proximo_ano, proximo_mes, proximo_dia)

    dias_para_mesversario = (proximo_mesversario - hoje).days

    return render_template(
        'calendario.html',
        data_inicio=data_inicio.strftime('%d/%m/%Y'),
        dias_juntos=dias_juntos,
        dias_para_mesversario=dias_para_mesversario,
        proximo_mesversario=proximo_mesversario.strftime('%d/%m/%Y')
    )

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

import os

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)

