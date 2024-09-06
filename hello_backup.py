import os
from flask import Flask, render_template, flash, request, redirect, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, ValidationError
from wtforms.validators import DataRequired, EqualTo, Length
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime 
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from datetime import date
from wtforms.widgets import TextArea
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user


#Criando uma instancia
app = Flask(__name__)
#Banco de dados antigo (SQLite)
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///usuarios.db'
#Novo Banco de Dados
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/users'
#Senha Secreta
app.config['SECRET_KEY'] = "12345678"
#Iniciando o banco de dados
db = SQLAlchemy(app)
migrate = Migrate(app, db)

#Pacote Flask_Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


#Criando o formulário de login

class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Senha", validators=[DataRequired()])
    submit = SubmitField("Enviar")


#Criando a página de login
@app.route('/login',methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(username=form.username.data).first()
        if user:
            #Checando a senha criptografada e comparando se a senha digitada no formulário (form.password.data) é a mesma
            #do DB (user.password_hash)
            if check_password_hash(user.password_hash, form.password.data):
                login_user(user)
                flash('Logado com sucesso')
                return redirect(url_for('dashboard'))
            else:
                flash('Senha Incorreta. Tente Novamente!')
        else:
            flash('Usuário não encontrado. Tente Novamente')

    return render_template('login.html', form = form)

#Criando a Página de Logout
@app.route('/logout', methods = ['GET', 'POST'])
#@login_required
def logout():
    logout_user()
    flash('Você foi desconectado!')
    return redirect(url_for('index'))

#Criando a página do Painel

@app.route('/dashboard',methods=['GET', 'POST'])
#Requer o login para acessar a página
#@login_required
def dashboard():
    form = UserForm()
    id = current_user.i
    name_to_update = Users.query.get_or_404(id)
    if request.method == "POST":
        name_to_update.name = request.form['name']
        name_to_update.username = request.form['username']
        name_to_update.email = request.form['email']
        try:
            db.session.commit()
            flash("Dados do usuário atualizados com sucesso!")
            return render_template("dashboard.html",
                                   form = form,
                                   name_to_update = name_to_update)
        except:
            flash("Erro. Tente novamente")
            return render_template("dashboard.html",
                                   form = form,
                                   name_to_update = name_to_update)
    else:
        return render_template("dashboard.html",
                                   form = form,
                                   name_to_update = name_to_update)
    
    return render_template('dashboard.html')

#Criando o Modelo de Post do Blog
class Posts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(280))
    content = db.Column(db.Text)
    author = db.Column(db.String(280))
    date_posted = db.Column(db.DateTime, default = datetime.utcnow)
    slug = db.Column(db.String(280))

# Criando o post no Blog
class PostForm(FlaskForm):
    title = StringField("Título", validators=[DataRequired()])
    content = StringField("Conteúdo", validators=[DataRequired()], widget=TextArea())
    author = StringField("Autor", validators=[DataRequired()])
    slug = StringField("Slug", validators=[DataRequired()])
    submit = SubmitField("Enviar")

@app.route('/posts')
def posts():
    #Reunindo todos os posts no banco de dados
    posts = Posts.query.order_by(Posts.date_posted)
    return render_template("posts.html", posts=posts)

#Página dos posts

@app.route('/posts/<int:id>')
def post(id):
    post = Posts.query.get_or_404(id)
    return render_template("post.html", post = post)

#Editando o post 

@app.route('/posts/edit_post/<int:id>', methods=['GET', 'POST'])
#@login_required
def edit_post(id):
    post = Posts.query.get_or_404(id)
    form = PostForm()
    if form.validate_on_submit():
        post.title = form.title.data
        post.author = form.author.data
        post.slug = form.slug.data
        post.content = form.content.data
    # atualização do banco de dancos 
        db.session.add(post)
        db.session.commit()
        flash('Post editado com sucesso!')
        return redirect(url_for('post', id=post.id))
    form.title.data = post.title
    form.author.data = post.author
    form.slug.data = post.slug
    form.content.data = post.content 
    return render_template('edit_post.html', form=form)
    
    
#Adicionar Página de Post
@app.route('/add_post', methods=['GET', 'POST'])
#@login_required
def add_post():
    form = PostForm()
    if form.validate_on_submit():
        post = Posts(title=form.title.data, content = form.content.data, author = form.author.data, slug = form.slug.data)
        #Limpando o form
        form.title.data = ''
        form.content.data = ''
        form.author.data = ''
        form.slug.data = ''

        #Adicionando o post no banco de dados
        db.session.add(post)
        db.session.commit()
        flash("Post publicado com sucesso!")

        #Redirencionando para a página 
        return render_template("add_post.html", form = form)
    
    return render_template("add_post.html", form = form)

# Json
@app.route('/date')
def get_current_date():
    return {"Date": date.today()}


#Criando o modelo
class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    username = db.Column(db.String(20), nullable = False, unique=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)

    #Senha
    password_hash = db.Column(db.String(128))

    @property
    def password(self):
        raise AttributeError('Essa senha não é válida!')
    
    #Criptografando a senha
    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    #Verificando a senha 
    def verify_password (self, password):   
        return check_password_hash(self.password_hash, password)    
    
    #Criando uma String
    def __repr__(self):
        return '<Name %r>' % self.name
    
# Criando uma classe formulário de nome

class NameForm(FlaskForm):
    name = StringField("Qual é o seu nome?", validators=[DataRequired()])
    submit = SubmitField("Enviar")

# Criando uma classe formulário do usuário 

class UserForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired()])
    username = StringField("Username", validators=[DataRequired()])
    password_hash = PasswordField('Senha', validators= [DataRequired(), EqualTo('password_hash2', message='As senhas devem ser iguais!')])
    password_hash2 = PasswordField('Confirme sua senha', validators= [DataRequired()])
    submit = SubmitField("Enviar")

# Criando a classe formulário da senha

class PasswordForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password_hash = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Enviar")

# Criando as rotas
@app.route('/')
def index():
    return render_template("index.html", methods=['GET', 'POST'])


#Atualizando os dados do Banco de dados
@app.route('/update/<int:id>', methods=['GET', 'POST'])
def update(id):
    form = UserForm()
    name_to_update = Users.query.get_or_404(id)
    if request.method == "POST":
        name_to_update.name = request.form['name']
        name_to_update.username = request.form['username']
        name_to_update.email = request.form['email']
        try:
            db.session.commit()
            flash("Dados do usuário atualizados com sucesso!")
            return render_template("update.html",
                                   form = form,
                                   name_to_update = name_to_update)
        except:
            flash("Erro. Tente novamente")
            return render_template("update.html",
                                   form = form,
                                   name_to_update = name_to_update)
    else:
        return render_template("update.html",
                                   form = form,
                                   name_to_update = name_to_update)

@app.route('/user/<name>')
def user(name):
    return render_template("user.html", user_name = name)

# Criando a rota da página Password 
@app.route('/test_pw', methods=['GET', 'POST'])
def teste_pw():
    email = None
    password = None
    pw_to_check = None
    passed = None
    form = PasswordForm()

    #Validando a senha
    if form.validate_on_submit():
        email = form.email.data
        password = form.password_hash.data
        form.email.data = ''
        form.password_hash.data = ''

        #Localizando o usuário pelo email
        pw_to_check = Users.query.filter_by(email=email).first()

        #Checando a senha 
        passed = check_password_hash(pw_to_check.password_hash, password)

        flash("Enviado com Sucesso!")

    return render_template("test_pw.html",
                           email = email,
                           password = password,
                           pw_to_check = pw_to_check,
                           passed = passed,
                           form = form)

# Criando a rota da página Name 
@app.route('/name', methods=['GET', 'POST'])
def name():
    name = None
    form = NameForm()
    #Validando o Nome
    if form.validate_on_submit():
        name = form.name.data
        form.name.data = ''
        flash("Enviado com Sucesso!")

    return render_template("name.html",
                           name = name,
                           form = form)

#Criando a rota da página "cadastro"
@app.route('/user/cadastro', methods=['GET', 'POST'])
def add_user():
    name = None
    form = UserForm()
    #Validando o nome 
    if form.validate_on_submit():
        user = Users.query.filter_by(email = form.email.data).first()
        #Se não ouver um email igual ao cadastrado, o usuário é cadastrado
        if user is None:
            hashed_pw = generate_password_hash(form.password_hash.data, "pbkdf2:sha256")
            user = Users(name = form.name.data, email = form.email.data, username = form.username.data, password_hash=hashed_pw)
            #Adicionando o nome e o email do usuário ao banco de dados:
            db.session.add(user)
            db.session.commit()
        name = form.name.data
        form.name.data = ''
        form.username.data = ''
        form.email.data = ''
        form.password_hash.data  = ''

        flash("Usuário Adicionado com sucesso!")
    our_users = Users.query.order_by(Users.date_added)#.all()

    return render_template("add_user.html", 
                           name = name,
                           our_users = our_users,
                           form = form)

#Deletar um usuário 

@app.route('/delete/<int:id>')
def delete(id):
    name = None
    form = UserForm()
    user_to_delete = Users.query.get_or_404(id)
    try:
        db.session.delete(user_to_delete)
        db.session.commit()
        flash("Usuário deletado com sucesso!")
        
        our_users = Users.query.order_by(Users.date_added)
        return render_template("add_user.html", 
                           name = name,
                           our_users = our_users,
                           form = form)
    except:   
        flash("Ops! Não foi possível deletar o usuário!") 
        return render_template("add_user.html", 
                           name = name,
                           our_users = our_users,
                           form = form)
    
@app.route('/delete_post/<int:id>')
#@login_required
def delete_post(id):
    post_to_delete = Posts.query.get_or_404(id)
    try:
        db.session.delete(post_to_delete)
        db.session.commit()
        flash("Post deletado com sucesso!")
        return redirect(url_for('posts'))
    except:
        flash("Ops! Não foi possível deletar o post!")
        return redirect(url_for('posts'))

#Páginas de Erro Personalizadas

#URL Inválido
@app.errorhandler(404)
def pagina_nao_encontrada(e):
    return render_template("404.html"), 404

#Erro interno do servidor
@app.errorhandler(500)
def pagina_nao_encontrada(e):
    return render_template("500.html"), 500

if __name__ == "__main__":
    os.environ["FLASK_ENV"] = "development"
    app.run(debug=True)