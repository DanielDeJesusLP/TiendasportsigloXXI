import json
import pyrebase
import os
from flask import Blueprint, redirect, render_template, request, send_file
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64



config = {
    "apiKey": "AIzaSyCYTonsY61ldDvZSb3FpeLZxMwUjsT84H4",
    "authDomain": "bancodanifo.firebaseapp.com",
    "databaseURL": "https://bancodanifo-default-rtdb.firebaseio.com",
    "projectId": "bancodanifo",
    "storageBucket": "bancodanifo.appspot.com",
    "messagingSenderId": "304043770972",
    "appId": "1:304043770972:web:eed42218b5b73a17291299"
}

app = Blueprint('registro', __name__, url_prefix='/')

firebase = pyrebase.initialize_app(config)
auth = firebase.auth()
db = firebase.database()

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

@app.route('/registrarme', methods=['POST'])
def registrarme():
    name = request.form['name']
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    number = request.form['number']

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    password_encrypted = private_key.public_key().encrypt(
        password.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

  
    password_encrypted_base64 = base64.b64encode(password_encrypted).decode('utf-8')

    

    try:
        user = auth.create_user_with_email_and_password(email, password)
        datos = {
            "name": name,
            "username": username,
            "email": email,
            "number": number,
            'password': password_encrypted_base64  # Almacena la contraseña encriptada en la base de datos
        }
        db.child('users').child(user['localId']).set(datos)
        return redirect('/login')
    except Exception as e:
        print(str(e))
        return redirect('/registro')


@app.route('/pagos', methods=['POST'])
def pagos():
    campos_cifrados = {
        "numero": request.form['numero'],
        "fecha": request.form['fecha'],
        "cvv": request.form['cvv']
    }

    datos_planos = {
        "nombre": request.form['nombre'],
        "banco": request.form['banco']
    }

    clave_aes = os.urandom(16)
    iv_aes = b'miivultrasecreta'  

    campos_cifrados_json = json.dumps(campos_cifrados).encode('utf-8')

    cipher = Cipher(algorithms.AES(clave_aes), modes.GCM(iv_aes), backend=default_backend())
    encryptor = cipher.encryptor()
    campos_cifrados_aes = encryptor.update(campos_cifrados_json) + encryptor.finalize()

    tag_aes = encryptor.tag

    campos_cifrados_base64 = base64.b64encode(campos_cifrados_aes).decode('utf-8')
    tag_base64 = base64.b64encode(tag_aes).decode('utf-8')

    datos_cifrados = {
        "campos_cifrados": campos_cifrados_base64,
        "tag_aes": tag_base64
    }

    datos_cifrados.update(datos_planos)

    db.child('pagos').push(datos_cifrados)
    print(datos_cifrados)
    print(datos_planos)
    print(campos_cifrados)
    return redirect('/producto')


with open('public_key.pem', 'rb') as key_file:
    public_key_pem = key_file.read()


public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())

@app.route('/regis', methods=['POST'])
def regis():
   
    nombre = request.form['nombre']
    correo = request.form['correo']
    telefono = request.form['telefono']
    asunto = request.form['asunto']
    mensaje_original = request.form['mensaje']

    mensaje_cifrado = public_key.encrypt(
        mensaje_original.encode('utf-8'),
        padding.OAEP(
           mgf=padding.MGF1(algorithm=hashes.SHA256()),
             algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Codifica el mensaje cifrado en base64 para almacenarlo en la base de datos
    mensaje_cifrado_base64 = base64.b64encode(mensaje_cifrado).decode('utf-8')

    # Almacena los datos cifrados en Firebase
    datos = {
        "nombre": nombre,
        "correo": correo,
        "telefono": telefono,
        "asunto": asunto,
        "mensaje": mensaje_cifrado_base64
    }

    db.child('contac').push(datos)  

    
    return redirect('/contacto')

@app.route('/datosencri')
def datosencri():
    # Obtener datos de Firebase
    contac_data = db.child('contac').get().val()

    # Convertir datos a una lista de diccionarios
    datos = []
    for key, value in contac_data.items():
        datos.append(value)

    print(datos)
    # Renderizar la plantilla HTML con los datos
    return render_template('/datoscontac.html', datos=datos)

# Lee la llave privada desde un archivo

with open('private_key.pem', 'rb') as key_file:
    private_key_pem = key_file.read()

# Crea un objeto de llave privada desde el PEM
private_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())

@app.route('/datos')
def datos():
    # Obtener datos de Firebase
    contac_data = db.child('contac').get().val()

    # Convertir datos a una lista de diccionarios
    datos = []
    for key, value in contac_data.items():
        try:
            mensaje_cifrado_base64 = value.get('mensaje', '')  
            mensaje_cifrado = base64.b64decode(mensaje_cifrado_base64)  

            mensaje_desencriptado = private_key.decrypt(
                mensaje_cifrado,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            ).decode('utf-8')

            value['mensaje'] = mensaje_desencriptado

        except ValueError as e:
            # Manejo del error específico de desencriptación
            print("Error en la desencriptación. Posible causa: clave incorrecta.")
            value['mensaje'] = "Error en la desencriptación hubo un cambio de administrador. Mensaje no disponible."
        except Exception as e:
            print(f"Ocurrió un error inesperado: {e}")
            value['mensaje'] = "Error inesperado. Mensaje no disponible."

        datos.append(value)
        

    return render_template('/datoscontac2.html', datos=datos)


def generar_llaves():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key = private_key.public_key()
    
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    
    with open('private_key.pem', 'wb') as f:
        f.write(private_key_pem)
    
    
    with open('public_key.pem', 'wb') as f:
        f.write(public_key_pem)

    return private_key_pem, public_key_pem



@app.route('/generar_llaves', methods=['POST'])
def generar_llaves_route():
    private_key_pem, public_key_pem = generar_llaves()
    return render_template('generar_llave2.html')