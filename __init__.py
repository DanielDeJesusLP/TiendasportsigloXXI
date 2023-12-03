import pyrebase
from features.backend import inicio, registro
from features.frontend import view
from flask import Flask

app = Flask(__name__)
app.secret_key = 'secret'

app.register_blueprint(view.app)
app.register_blueprint(registro.app)
app.register_blueprint(inicio.app)

if __name__ == "__main__":
  app.run(debug=True)

