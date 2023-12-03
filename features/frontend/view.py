from flask import Blueprint, render_template, redirect, session, request, url_for

app = Blueprint('main', __name__, url_prefix='/')


@app.route('/iniciar')
def iniciar():
    return render_template('home.html')

@app.route('/')
def inicio():
    return render_template('home.html')

@app.route('/home')
def home():
   return render_template('home.html')

@app.route('/home2')
def home2():
    if 'usuario' in session:
        return render_template('home2.html', usuario=session['usuario'])
    else:
        return redirect('/login')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/registro')
def registro():
        return render_template('registro.html')

@app.route('/contacto')
def contacto():
        return render_template('contacto.html')

@app.route('/pago')
def pago():
    if 'usuario' in session:
        return render_template('pago.html', usuario=session['usuario'])
    else:
        return redirect('/login')

@app.route('/producto')
def producto():
    if 'usuario' in session:
        return render_template('producto.html', usuario=session['usuario'])
    else:
        return redirect('/login')

@app.route('/admindatos')
def admindatos():
    if 'usuario2' in session:
        return render_template('admindatos.html', usuario=session['usuario'])
    else:
        return redirect('/login')


@app.route('/generar_llave')
def generar_llave():
    if 'usuario2' in session:
        return render_template('generar_llave.html', usuario=session['usuario2'])
    else:
        return redirect('/login')

@app.route('/aviso')
def aviso():
    return render_template('/aviso.html')

@app.route('/carrito')
def carrito():
    if 'usuario' in session:
        return render_template('carrito.html', usuario=session['usuario'])
    else:
        return redirect('/login')

@app.route('/generar_llave2')
def generar_llave2():
    if 'usuario2' in session:
        return render_template('generar_llave2.html', usuario=session['usuario2'])
    else:
        return redirect('/login')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/home')


if __name__ == '__main__':
    app.run(debug=True)
