import os
from flask import Flask, render_template, flash, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from webforms import LoginForm, PostForm, UserForm, PasswordForm, NameForm, SearchForm
from flask_ckeditor import CKEditor
from werkzeug.utils import secure_filename
import uuid as uuid

# Criando uma instância
app = Flask(__name__)
#Adicionando o CKEditor
CKEditor = CKEditor(app)
# Novo Banco de Dados
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/users'
# Senha Secreta
app.config['SECRET_KEY'] = "12345678"
app.config['UPLOAD_FOLDER'] = 'static/images/'
# Iniciando o banco de dados
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Pacote Flask_Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Passando as informações para o Navbar
@app.context_processor
def base():
    form = SearchForm()
    return dict(form = form)

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

# Criando Página do Administrador
@app.route('/admin')
@login_required
def admin():
    id = current_user.id
    if id == 21:
        return render_template("admin.html")
    else:
        flash("Desculpe, mas parece que você não é a gossip girl!")
        return redirect(url_for("index.html"))

#Criar uma função de pesquisar
@app.route('/search', methods=["POST"])
def search():
    form = SearchForm()
    posts = Posts.query
    if form.validate_on_submit():
        #Pegar dados no formulário de submissão
        post.searched = form.searched.data
        #Consultar o banco de dados
        posts = posts.filter(Posts.content.like('%' + post.searched + '%'))
        posts = posts.order_by(Posts.title).all()

        return render_template("search.html", 
                               form = form,
                               posts = posts,
                               searched = post.searched)

# Criando a página de login
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            flash('Logado com sucesso')
            return redirect(url_for('dashboard'))
        else:
            flash('Usuário ou senha incorretos. Tente novamente!')
    return render_template('login.html', form=form)

# Criando a Página de Logout
@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    flash('Você foi desconectado!')
    return redirect(url_for('index'))

# Criando a página do Painel
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    form = UserForm()
    id = current_user.id
    name_to_update = Users.query.get_or_404(id)
    if request.method == "POST":
        name_to_update.name = request.form['name']
        name_to_update.username = request.form['username']
        name_to_update.email = request.form['email']
        name_to_update.profile_pic = request.files['profile_pic']
        #Pegar nome da imagem
        pic_filename = secure_filename(name_to_update.profile_pic.filename)
        #Set UUID
        pic_name = str(uuid.uuid1()) + '_' + pic_filename
        #Salvando a imagem 
        saver = request.files['profile_pic']
        #Mudando para uma string para salvar no banco de dados
        name_to_update.profile_pic = pic_name
        try:
            db.session.commit()
            saver.save(os.path.join(app.config['UPLOAD_FOLDER']), pic_name)
            flash("Dados do usuário atualizados com sucesso!")
        except:
            flash("Erro. Tente novamente")
    return render_template("dashboard.html", form=form, name_to_update=name_to_update)

# Criando o Modelo de Post do Blog
class Posts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(280))
    content = db.Column(db.Text)
    #author = db.Column(db.String(280))
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    slug = db.Column(db.String(280))
    # Chave estrangeira para vincular usuários (referência à chave primária do usuário)
    #Usando o id da class Users (users.id)
    poster_id = db.Column(db.Integer, db.ForeignKey('users.id'))


@app.route('/posts')
def posts():
    # Reunindo todos os posts no banco de dados
    posts = Posts.query.order_by(Posts.date_posted.desc())
    return render_template("posts.html", posts=posts)

# Página dos posts
@app.route('/posts/<int:id>')
def post(id):
    post = Posts.query.get_or_404(id)
    return render_template("post.html", post=post)

# Editando o post
@app.route('/posts/edit_post/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_post(id):
    post = Posts.query.get_or_404(id)
    form = PostForm()
    if form.validate_on_submit():
        post.title = form.title.data
        #post.author = form.author.data
        post.slug = form.slug.data
        post.content = form.content.data
        db.session.commit()
        flash('Post editado com sucesso!')
        return redirect(url_for('post', id=post.id))
    
    if current_user.id == post.poster_id:
        form.title.data = post.title
        #form.author.data = post.author
        form.slug.data = post.slug
        form.content.data = post.content
        return render_template('edit_post.html', form=form)
    else:
        flash("Vocẽ não está autorizado a editar esse post")
        posts = Posts.query.order_by(Posts.date_posted.desc())
        return render_template("posts.html", posts=posts)

# Adicionar Página de Post
@app.route('/add_post', methods=['GET', 'POST'])
@login_required
def add_post():
    form = PostForm()
    if form.validate_on_submit():
        poster = current_user.id
        post = Posts(title=form.title.data, content=form.content.data, poster_id=poster, slug=form.slug.data)
        form.title.data = ''
        form.content.data = ''
        #form.author.data = ''
        form.slug.data = ''
        
        db.session.add(post)
        db.session.commit()
        flash("Post publicado com sucesso!")
        return redirect(url_for('posts'))
    return render_template("add_post.html", form=form)

# Json
@app.route('/date')
def get_current_date():
    return {"Date": date.today()}

# Criando o modelo
class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    username = db.Column(db.String(20), nullable=False, unique=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    profile_pic = db.Column(db.String(255), nullable=True)
    # Relacionamento com posts
    poster = db.relationship('Posts', backref='poster')

    # Senha
    password_hash = db.Column(db.String(128))

    @property
    def password(self):
        raise AttributeError('Essa senha não é válida!')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return '<Name %r>' % self.name

# Criando as rotas
@app.route('/')
def index():
    return render_template("index.html")

# Atualizando os dados do Banco de dados
@app.route('/update/<int:id>', methods=['GET', 'POST'])
@login_required
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
        except:
            flash("Erro. Tente novamente")
    return render_template("update.html", form=form, name_to_update=name_to_update)

@app.route('/user/<name>')
def user(name):
    return render_template("user.html", user_name=name)

# Criando a rota da página Password
@app.route('/test_pw', methods=['GET', 'POST'])
def teste_pw():
    email = None
    password = None
    pw_to_check = None
    passed = None
    form = PasswordForm()

    if form.validate_on_submit():
        email = form.email.data
        password = form.password_hash.data
        form.email.data = ''
        form.password_hash.data = ''

        pw_to_check = Users.query.filter_by(email=email).first()
        if pw_to_check:
            passed = check_password_hash(pw_to_check.password_hash, password)

        flash("Enviado com Sucesso!")

    return render_template("test_pw.html", email=email, password=password, pw_to_check=pw_to_check, passed=passed, form=form)

# Criando a rota da página "cadastro"
@app.route('/user/cadastro', methods=['GET', 'POST'])
def add_user():
    name = None
    form = UserForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()
        if user is None:
            hashed_pw = generate_password_hash(form.password_hash.data, "pbkdf2:sha256")
            user = Users(name=form.name.data, email=form.email.data, username=form.username.data, password_hash=hashed_pw)
            db.session.add(user)
            db.session.commit()                         
        name = form.name.data
        form.name.data = ''
        form.username.data = ''
        form.email.data = ''
        form.password_hash.data = ''

        flash("Usuário Adicionado com sucesso!")
    our_users = Users.query.order_by(Users.date_added).all()

    return render_template("add_user.html", name=name, our_users=our_users, form=form)

# Deletar um usuário
@app.route('/delete/<int:id>')
@login_required
def delete(id):
    name = None
    form = UserForm()
    user_to_delete = Users.query.get_or_404(id)
    try:
        db.session.delete(user_to_delete)
        db.session.commit()
        flash("Usuário deletado com sucesso!")
    except:
        flash("Ops! Não foi possível deletar o usuário!")
    our_users = Users.query.order_by(Users.date_added).all()
    return render_template("add_user.html", name=name, our_users=our_users, form=form)


#Atualização: Apenas o usuário que criou o post pode deletar ele.
@app.route('/delete_post/<int:id>')
@login_required
def delete_post(id):
    post_to_delete = Posts.query.get_or_404(id)
    id = current_user.id
    if id == post_to_delete.poster.id:
        try:
            db.session.delete(post_to_delete)
            db.session.commit()
            flash("Post deletado com sucesso!")
            post = Posts.query.order_by(Posts.date_posted)
            return redirect(url_for('posts'))
        except:
            flash("Ops! Não foi possível deletar o post!")
            return redirect(url_for('posts'))
            

    else:
        flash("Você não está autorizado a deletar esse post")
        post = Posts.query.order_by(Posts.date_posted)
        return redirect(url_for('posts'))


# Páginas de Erro Personalizadas
@app.errorhandler(404)
def pagina_nao_encontrada(e):
    return render_template("404.html"), 404

@app.errorhandler(500)
def erro_interno(e):
    return render_template("500.html"), 500

if __name__ == "__main__":
    os.environ["FLASK_ENV"] = "development"
    app.run(debug=True)
