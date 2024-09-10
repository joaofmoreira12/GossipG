from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, ValidationError
from wtforms.validators import DataRequired, EqualTo, Length
from wtforms.widgets import TextArea
from flask_ckeditor import CKEditorField


#Criando o formulário de Pesquisa

class SearchForm(FlaskForm):
    searched = StringField("Pesquisa", validators=[DataRequired()])
    submit = SubmitField("Enviar")


#Criando o formulário de login

class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Senha", validators=[DataRequired()])
    submit = SubmitField("Enviar")

    # Criando o post no Blog
class PostForm(FlaskForm):
    title = StringField("Título", validators=[DataRequired()])
    content = CKEditorField('Conteúdo', validators=[DataRequired()])
    #content = StringField("Conteúdo", validators=[DataRequired()], widget=TextArea())
    #author = StringField("Autor")
    slug = StringField("Slug", validators=[DataRequired()])
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

    # Criando uma classe formulário de nome

class NameForm(FlaskForm):
    name = StringField("Qual é o seu nome?", validators=[DataRequired()])
    submit = SubmitField("Enviar")