import os
from flask import Flask, render_template

app = Flask(__name__)

@app.route('/')

def index():
    favorite_pizza = ["frango", "carne seca", "chocolate com morango", 723728]
    return render_template("index.html", favorite_pizzaa = favorite_pizza)

@app.route('/user/<name>')

def user(name):
    return render_template("user.html", user_name = name)

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
