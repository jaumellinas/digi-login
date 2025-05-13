from flask import Flask, render_template, request, redirect, url_for, session, flash
import os
import logging
from dotenv import load_dotenv
from supabase import create_client, Client

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Cargar variables de entorno
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'una_clave_secreta_muy_segura')

# Configuración de Supabase
supabase_url = os.getenv('SUPABASE_URL')
supabase_key = os.getenv('SUPABASE_KEY')
supabase: Client = create_client(supabase_url, supabase_key)

@app.route('/')
def index():
    # Si el usuario ya está autenticado, redirigir a la página de bienvenida
    if 'user_id' in session:
        return redirect(url_for('welcome'))
    
    # URL base para redirecciones después de login
    # Asegúrate de que esta URL sea accesible desde internet si estás usando Supabase Cloud
    redirect_url = request.url_root.rstrip('/') + url_for('auth_callback')
    
    # Para desarrollo local, podrías necesitar una URL fija
    # redirect_url = "http://localhost:5000/auth/callback"
    
    logger.info(f"URL de redirección configurada: {redirect_url}")
    
    # Generar URLs para los diferentes proveedores
    auth_urls = {
        'github': f"{supabase_url}/auth/v1/authorize?provider=github&redirect_to={redirect_url}",
        'azure': f"{supabase_url}/auth/v1/authorize?provider=azure&redirect_to={redirect_url}&scopes=email+profile+openid+User.Read",
        'google': f"{supabase_url}/auth/v1/authorize?provider=google&redirect_to={redirect_url}"
    }
    
    return render_template('login.html', auth_urls=auth_urls)

@app.route('/auth/callback')
def auth_callback():
    # Obtener el token de acceso desde los parámetros de la URL
    access_token = request.args.get('access_token')
    refresh_token = request.args.get('refresh_token')
    
    # Verificar si hay mensaje de error
    error = request.args.get('error')
    error_description = request.args.get('error_description')
    
    if error:
        logger.error(f"Error de autenticación: {error} - {error_description}")
        return render_template('error.html', error=error, description=error_description)
    
    # Verificar si hay un código de autenticación (flujo OAuth)
    code = request.args.get('code')
    if code:
        try:
            # Obtener tokens usando el código de autorización
            auth_response = supabase.auth.exchange_code_for_session(
                {"auth_code": code}
            )
            
            # Extraer tokens
            access_token = auth_response.session.access_token
            
            # Proceder con la autenticación
            logger.info("Autenticación exitosa con código OAuth")
        except Exception as e:
            logger.error(f"Error intercambiando código por token: {e}")
            return render_template('error.html', error="Error de autenticación", description=str(e))
    
    if not access_token:
        # Si no hay token, puede ser un error o cancelación
        logger.warning("No se encontró token de acceso en la respuesta")
        return redirect(url_for('index'))
    
    try:
        # Obtener la información del usuario con el token
        user = supabase.auth.get_user(access_token)
        
        # Guardar información importante en la sesión
        session['user_id'] = user.user.id
        session['access_token'] = access_token
        
        # Intentar obtener el nombre de diferentes ubicaciones potenciales
        user_metadata = user.user.user_metadata
        if user_metadata:
            user_name = user_metadata.get('full_name') or user_metadata.get('name') or user_metadata.get('email')
        else:
            user_name = user.user.email
            
        session['user_name'] = user_name if user_name else 'Usuario'
        
        # Determinar el proveedor utilizado
        identity_providers = user.user.identities
        if identity_providers and len(identity_providers) > 0:
            session['provider'] = identity_providers[0].get('provider', 'desconocido')
        else:
            session['provider'] = 'desconocido'
        
        logger.info(f"Usuario autenticado correctamente: {user_name} con proveedor {session['provider']}")
        
        return redirect(url_for('welcome'))
    
    except Exception as e:
        logger.error(f"Error de autenticación: {e}")
        return render_template('error.html', error="Error de autenticación", description=str(e))

@app.route('/welcome')
def welcome():
    # Verificar si el usuario está autenticado
    if 'user_id' not in session:
        logger.warning("Intento de acceso a /welcome sin autenticación")
        return redirect(url_for('index'))
    
    user_name = session.get('user_name', 'Usuario')
    provider = session.get('provider', 'proveedor desconocido')
    
    # Convertir el proveedor a un formato más legible
    provider_display = {
        'github': 'GitHub',
        'azure': 'Microsoft Azure',
        'google': 'Google',
        'desconocido': 'un proveedor desconocido'
    }.get(provider, provider)
    
    logger.info(f"Mostrando página de bienvenida para {user_name} autenticado con {provider_display}")
    
    # Para depuración, incluimos información de la sesión
    debug_info = None
    if app.debug:
        debug_info = {
            'session_keys': list(session.keys()),
            'provider': provider,
            'user_id': session.get('user_id')
        }
    
    return render_template('welcome.html', user=user_name, provider=provider_display, debug_info=debug_info)

@app.route('/logout')
def logout():
    # Si hay un token de acceso, intentar cerrar sesión en Supabase también
    if 'access_token' in session:
        try:
            supabase.auth.sign_out(session['access_token'])
            logger.info("Sesión cerrada en Supabase correctamente")
        except Exception as e:
            logger.error(f"Error al cerrar sesión en Supabase: {e}")
    
    # Eliminar datos de sesión
    session.clear()
    logger.info("Sesión local eliminada correctamente")
    
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)