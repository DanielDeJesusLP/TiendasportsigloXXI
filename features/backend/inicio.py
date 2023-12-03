import pyrebase
from flask import Blueprint, request, session, redirect, render_template,url_for
from datetime import datetime, timedelta
app = Blueprint('sesion', __name__, url_prefix='/sesion')

# Configuración de Firebase
config = {
    "apiKey": "AIzaSyCYTonsY61ldDvZSb3FpeLZxMwUjsT84H4",
    "authDomain": "bancodanifo.firebaseapp.com",
    "databaseURL": "https://bancodanifo-default-rtdb.firebaseio.com",
    "projectId": "bancodanifo",
    "storageBucket": "bancodanifo.appspot.com",
    "messagingSenderId": "304043770972",
    "appId": "1:304043770972:web:eed42218b5b73a17291299"
}

firebase = pyrebase.initialize_app(config)
auth = firebase.auth()

@app.route('/iniciar', methods=['GET', 'POST'])
def iniciar_sesion():
  
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        try:
            user = auth.sign_in_with_email_and_password(email, password)

            if email == 'daniel@gmail.com' and password == '123456':
                session['usuario2'] = email
                return redirect('/generar_llave')
            else:
                session['usuario'] = email
                return redirect('/home2')
        except Exception as e:
            print(str(e))
            return redirect('/login')

    return render_template('login.html')


@app.route('/registrarse', methods=['POST'])
def registrarse():
    email = request.form['email']
    password = request.form['password']

    try:
        auth.create_user_with_email_and_password(email, password)
        # Nuevo usuario registrado correctamente
        return redirect('/login')  
    except Exception as e:
        
        print(str(e)) 
        return redirect('/registro') 
    

