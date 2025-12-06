import os
import random  
import string  
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message # IMPORTANTE: Importar Mail
from datetime import datetime 

app = Flask(__name__)


# --- CONFIGURACIÓN DE LA BASE DE DATOS INTELIGENTE ---
database_url = os.environ.get('DATABASE_URL')

if database_url and database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

# Instrucción 1: La URI de la base de datos
app.config['SQLALCHEMY_DATABASE_URI'] = database_url or 'postgresql://postgres:gfiguera@localhost:5432/SQLALCHEMY_DATABASE_URI?client_encoding=UTF8'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'una_clave_secreta_muy_segura'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}


# --- CONFIGURACIÓN DE CORREO GMAIL ---
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'fundacionhuellaalcorazonsoport@gmail.com'
# ¡IMPORTANTE! AQUÍ DEBES PONER LA CONTRASEÑA DE APLICACIÓN DE GOOGLE, NO TU CLAVE NORMAL
app.config['MAIL_PASSWORD'] = 'ftsh ecbn ovql xbom' 
app.config['MAIL_DEFAULT_SENDER'] = 'fundacionhuellaalcorazonsoport@gmail.com'


mail = Mail(app)
db = SQLAlchemy(app)

# --- Configuración de Flask-Login ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login_page'

@login_manager.user_loader
def load_user(user_id):
    # CORRECCIÓN: Asegurarse de que el ID es un entero
    return User.query.get(int(user_id))

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# --- FUNCIONES AUXILIARES ---
def parse_date(date_str):
    if not date_str:
        return None
    try:
        return datetime.strptime(date_str, '%Y-%m-%d').date()
    except ValueError:
        return None

# ==========================================
#       MODELOS DE BASE DE DATOS
# ==========================================

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    cedula = db.Column(db.String(20), unique=True, nullable=False) 
    password_hash = db.Column(db.String(512))
    
    adopted_dogs = db.relationship('DogForAdoption', backref='owner', lazy=True)
    requests = db.relationship('Adopter', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class DogForAdoption(db.Model):
    __tablename__ = 'dogs_for_adoption'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    sex = db.Column(db.String(10), nullable=False)
    age = db.Column(db.String(50), nullable=False)
    weight = db.Column(db.String(20))
    size = db.Column(db.String(20))
    breed = db.Column(db.String(50))
    color = db.Column(db.String(50))
    rescuer = db.Column(db.String(100))
    origin = db.Column(db.String(200))
    arrival_date = db.Column(db.Date)
    arrival_condition = db.Column(db.Text)
    birth_date = db.Column(db.Date, nullable=True)
    litter_number = db.Column(db.String(50))
    deworming_status = db.Column(db.String(200))
    vaccination_status = db.Column(db.String(200))
    exams = db.Column(db.Text)
    diseases = db.Column(db.Text)
    treatments = db.Column(db.Text)
    health_status = db.Column(db.String(50))
    photo_path = db.Column(db.String(255), nullable=False)
    is_adopted = db.Column(db.Boolean, default=False)
    adoption_date = db.Column(db.Date, nullable=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    photo_adoption_day = db.Column(db.String(255), nullable=True)
    photo_followup = db.Column(db.String(255), nullable=True)
    adoption_requests = db.relationship('Adopter', backref='dog', lazy=True)

   
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'sex': self.sex,
            'age': self.age,
            'weight': self.weight,
            'size': self.size,
            'breed': self.breed,
            'color': self.color,
            'rescuer': self.rescuer,
            'origin': self.origin,
            'arrival_date': self.arrival_date.isoformat() if self.arrival_date else None,
            'arrival_condition': self.arrival_condition,
            'birth_date': self.birth_date.isoformat() if self.birth_date else None,
            'litter_number': self.litter_number,
            'deworming_status': self.deworming_status,
            'vaccination_status': self.vaccination_status,
            'exams': self.exams,
            'diseases': self.diseases,
            'treatments': self.treatments,
            'health_status': self.health_status,
            'photo_path': self.photo_path
        }
    # --- 

class Adopter(db.Model):
    __tablename__ = 'adopters'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20))
    address = db.Column(db.String(200))
    rif = db.Column(db.String(20), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    dog_id = db.Column(db.Integer, db.ForeignKey('dogs_for_adoption.id'), nullable=False)
    status = db.Column(db.String(20), default='Pendiente')
    request_date = db.Column(db.DateTime, default=datetime.utcnow)

class Event(db.Model):
    __tablename__ = 'events'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    date = db.Column(db.Date, nullable=False)
    time = db.Column(db.Time, nullable=False)
    end_time = db.Column(db.Time, nullable=False)
    location = db.Column(db.String(200), nullable=True)
    description = db.Column(db.Text, nullable=False)
    photo_path = db.Column(db.String(255), nullable=True)

    def to_dict(self):
        def format_time_ampm(t):
            if isinstance(t, str):
                from datetime import time as time_obj
                t = time_obj.fromisoformat(t)
            return t.strftime('%I:%M %p')
        return {
            'id': self.id, 'title': self.title, 'date': self.date.isoformat(),
            'time': format_time_ampm(self.time), 'end_time': format_time_ampm(self.end_time),
            'location': self.location, 'description': self.description, 'photo_path': self.photo_path
        }


# Modelo para las fotos del sitio (Inicio)
class SitePhoto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    section = db.Column(db.String(50)) # 'hero', 'about_1', 'about_2', 'about_3', 'about_4'
    photo_path = db.Column(db.String(255), nullable=False)


@app.route('/')
def index():
    # Cargar fotos dinámicas
    hero_photos = SitePhoto.query.filter_by(section='hero').all()
    
    # Fotos de Quiénes Somos (usamos un diccionario para fácil acceso en HTML)
    about_photos = {
        'about_1': SitePhoto.query.filter_by(section='about_1').first(),
        'about_2': SitePhoto.query.filter_by(section='about_2').first(),
        'about_3': SitePhoto.query.filter_by(section='about_3').first(),
        'about_4': SitePhoto.query.filter_by(section='about_4').first()
    }

    return render_template('index.html', 
                           logged_in=current_user.is_authenticated, 
                           username=current_user.username if current_user.is_authenticated else None, 
                           current_user=current_user,
                           hero_photos=hero_photos,
                           about_photos=about_photos)
@app.route('/contact')
def contact_page():
    return render_template('contact.html', logged_in=current_user.is_authenticated, username=current_user.username if current_user.is_authenticated else None, current_user=current_user)

@app.route('/events')
def events_page():
    try:
        event_objects = Event.query.order_by(Event.date.asc()).all()
        events_serializable = [event.to_dict() for event in event_objects]
    except: events_serializable = []
    return render_template('events.html', events=events_serializable, logged_in=current_user.is_authenticated, username=current_user.username if current_user.is_authenticated else None, current_user=current_user)

@app.route('/schedule')
def schedule_page():
    is_admin = current_user.is_authenticated and current_user.username == 'gfiguera'
    return render_template('schedule.html', logged_in=current_user.is_authenticated, username=current_user.username if current_user.is_authenticated else None, is_admin=is_admin, current_user=current_user)

@app.route('/how-to-help')
def how_to_help():
    return render_template('how_to_help.html', logged_in=current_user.is_authenticated, username=current_user.username if current_user.is_authenticated else None, current_user=current_user)

@app.route('/faq')
def faq():
    return render_template('faq.html', logged_in=current_user.is_authenticated, username=current_user.username if current_user.is_authenticated else None, current_user=current_user)

# --- GESTIÓN DE ADOPCIONES ---

@app.route('/adopt')
def adopt():
    dogs = DogForAdoption.query.filter_by(is_adopted=False).all()
    is_admin = current_user.is_authenticated and current_user.username == 'gfiguera'
    return render_template('adopt.html',
                           logged_in=current_user.is_authenticated,
                           username=current_user.username if current_user.is_authenticated else None,
                           is_admin=is_admin,
                           dogs=dogs,
                           current_user=current_user)

@app.route('/upload_dog', methods=['POST'])
@login_required
def upload_dog():
    if current_user.username != 'gfiguera':
        flash('No autorizado', 'error')
        return redirect(url_for('adopt'))

    file = request.files.get('photo')
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        new_dog = DogForAdoption(
            name=request.form['name'],
            sex=request.form['sex'],
            age=request.form['age'],
            weight=request.form.get('weight'),
            size=request.form.get('size'),
            breed=request.form.get('breed'),
            color=request.form.get('color'),
            rescuer=request.form.get('rescuer'),
            origin=request.form.get('origin'),
            arrival_date=parse_date(request.form.get('arrival_date')),
            arrival_condition=request.form.get('arrival_condition'),
            birth_date=parse_date(request.form.get('birth_date')),
            litter_number=request.form.get('litter_number'),
            deworming_status=request.form.get('deworming_status'),
            vaccination_status=request.form.get('vaccination_status'),
            exams=request.form.get('exams'),
            diseases=request.form.get('diseases'),
            treatments=request.form.get('treatments'),
            health_status=request.form.get('health_status'),
            photo_path=filename
        )
        db.session.add(new_dog)
        db.session.commit()
        flash('¡Ficha creada!', 'success')
    else:
        flash('Error en la foto', 'error')
    return redirect(url_for('adopt'))

# --- FLUJO DE SOLICITUD DE ADOPCIÓN (LÓGICA UNIFICADA) ---

@app.route('/adopt-request/<int:dog_id>')
def adopt_request_form(dog_id):
    dog = DogForAdoption.query.get_or_404(dog_id)
    return render_template('adopter_form.html', 
                           dog=dog, 
                           logged_in=current_user.is_authenticated, 
                           current_user=current_user)

@app.route('/submit_adoption_request', methods=['POST'])
def submit_adoption_request():
    dog_id = request.form.get('dog_id')
    dog = DogForAdoption.query.get(dog_id)
    
    if not dog:
        flash('Error: Perro no encontrado.', 'error')
        return redirect(url_for('adopt'))

    user = current_user
    
    if not current_user.is_authenticated:
        # Si no está logueado, crea el usuario
        username = request.form.get('username')
        email = request.form.get('email')
        cedula = request.form.get('cedula')
        password = request.form.get('password')
        
        if User.query.filter((User.username==username) | (User.cedula==cedula)).first():
            flash('El usuario o cédula ya existe. Por favor, inicia sesión.', 'error')
            return redirect(url_for('adopt_request_form', dog_id=dog_id))
            
        try:
            new_user = User(username=username, email=email, cedula=cedula)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            user = new_user
        except Exception as e:
            db.session.rollback()
            flash(f'Error creando usuario: {str(e)}', 'error')
            return redirect(url_for('adopt_request_form', dog_id=dog_id))

    # Ahora, crea la solicitud de adopción
    try:
        new_req = Adopter(
            user_id=user.id,
            dog_id=dog.id,
            name=request.form.get('fullname'),
            phone=request.form.get('phone'),
            address=request.form.get('address'),
            rif=request.form.get('rif'),
            status='Pendiente'
        )
        db.session.add(new_req)
        db.session.commit()
        flash('¡Solicitud enviada con éxito! El administrador la revisará.', 'success')
        return redirect(url_for('my_adoptions'))
    except Exception as e:
        db.session.rollback()
        flash(f'Error al enviar solicitud: {str(e)}', 'error')
        return redirect(url_for('adopt'))

# --- PANEL DE ADMINISTRACIÓN ---

@app.route('/admin')
@login_required
def admin():
    if current_user.username != 'gfiguera':
        return redirect(url_for('index'))
    
    pending = Adopter.query.filter_by(status='Pendiente').all()
    register_url = url_for('adopt', _external=True) 
    
    return render_template('admin.html', 
                           username=current_user.username, 
                           logged_in=True, 
                           is_admin=True, 
                           pending_requests=pending,
                           register_form_url=register_url,
                           current_user=current_user)

@app.route('/approve_adoption/<int:req_id>', methods=['POST'])
@login_required
def approve_adoption(req_id):
    if current_user.username != 'gfiguera': return jsonify({'success':False})
    
    req = Adopter.query.get_or_404(req_id)
    dog = DogForAdoption.query.get(req.dog_id)
    user = User.query.get(req.user_id)
    
    if dog and user:
        dog.owner_id = user.id
        dog.is_adopted = True
        dog.adoption_date = datetime.now().date()
        req.status = 'Aprobada'
        
        others = Adopter.query.filter(Adopter.dog_id==dog.id, Adopter.id!=req.id).all()
        for o in others: o.status = 'Cerrada'
        
        db.session.commit()
        return jsonify({'success':True, 'message': 'Adopción aprobada.'})
    return jsonify({'success':False, 'message':'Error de datos'})

# --- PANEL DE USUARIO (MIS ADOPCIONES) ---

@app.route('/my_adoptions')
@login_required
def my_adoptions():
    my_dogs = DogForAdoption.query.filter_by(owner_id=current_user.id).all()
    my_requests = Adopter.query.filter_by(user_id=current_user.id).all()

    current_date = datetime.now().date()
    return render_template('my_adoptions.html', dogs=my_dogs, requests=my_requests, username=current_user.username, logged_in=True, current_user=current_user, current_date=current_date)



@app.route('/upload_followup/<int:dog_id>', methods=['POST'])
@login_required
def upload_followup(dog_id):
    dog = DogForAdoption.query.get_or_404(dog_id)
    if dog.owner_id != current_user.id and current_user.username != 'gfiguera':
        flash('No autorizado', 'error')
        return redirect(url_for('my_adoptions'))
        
    type_p = request.form.get('type_photo')
    file = request.files.get('photo')
    if file and allowed_file(file.filename):
        filename = secure_filename(f"{type_p}_{dog.id}_{file.filename}")
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        if type_p == 'adoption_day': dog.photo_adoption_day = filename
        elif type_p == 'followup': dog.photo_followup = filename
        db.session.commit()
        flash('Foto subida', 'success')
    return redirect(url_for('my_adoptions'))

# --- EDICIÓN Y ELIMINACIÓN DE PERROS (Rutas de Admin) ---
@app.route('/edit_dog/<int:dog_id>', methods=['POST'])
@login_required
def edit_dog(dog_id):
    if current_user.username != 'gfiguera':
        return jsonify({'success': False, 'message': 'No tienes permiso.'}), 403

    dog = DogForAdoption.query.get(dog_id)
    if not dog:
        return jsonify({'success': False, 'message': 'Cachorro no encontrado.'}), 404
    
    data = request.get_json()
    
    try:
        # Actualiza todos los campos de la ficha
        dog.name = data.get('name', dog.name)
        dog.sex = data.get('sex', dog.sex)
        dog.age = data.get('age', dog.age)
        dog.weight = data.get('weight')
        dog.size = data.get('size')
        dog.breed = data.get('breed')
        dog.color = data.get('color')
        
        dog.rescuer = data.get('rescuer')
        dog.origin = data.get('origin') # CORREGIDO (antes 'gcoet')
        dog.arrival_date = parse_date(data.get('arrival_date'))
        dog.arrival_condition = data.get('arrival_condition')
        
        dog.litter_number = data.get('litter_number')
        
        dog.deworming_status = data.get('deworming_status')
        dog.vaccination_status = data.get('vaccination_status')
        dog.exams = data.get('exams')
        dog.diseases = data.get('diseases')
        dog.treatments = data.get('treatments')
        dog.health_status = data.get('health_status')

        db.session.commit()
        return jsonify({'success': True, 'message': f'Ficha de {dog.name} actualizada.'})

    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Error al actualizar: {str(e)}'}), 500

@app.route('/delete_dog/<int:dog_id>', methods=['POST'])
@login_required
def delete_dog(dog_id):
    if current_user.username != 'gfiguera':
        return jsonify({'success': False, 'message': 'No tienes permiso.'}), 403
    dog_to_delete = DogForAdoption.query.get(dog_id)
    if not dog_to_delete:
        return jsonify({'success': False, 'message': 'Cachorro no encontrado.'}), 404
    try:
        # (Lógica para borrar imagen)
        if dog_to_delete.photo_path:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], dog_to_delete.photo_path)
            if os.path.exists(file_path): os.remove(file_path)
    except Exception as e:
        print(f"Error al eliminar imagen: {e}")
        
    db.session.delete(dog_to_delete)
    db.session.commit()
    return jsonify({'success': True, 'message': 'Cachorro eliminado.'})

# --- AUTENTICACIÓN Y REGISTRO ---
@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if current_user.is_authenticated: return redirect(url_for('index'))
    
    if request.method == 'POST':
        data = request.get_json()
        user = User.query.filter_by(username=data.get('username')).first()
        
        if user and user.check_password(data.get('password')):
            login_user(user)
            
            # --- LÓGICA DE REDIRECCIÓN ---
            # Si el frontend nos manda "next_url", usamos esa. Si no, al index.
            next_page = data.get('next_url')
            
            if next_page:
                target_url = next_page # Ir a cambiar contraseña
            else:
                target_url = url_for('index') # Ir al inicio normal
            
            return jsonify({'success': True, 'redirect_url': target_url})
            # -----------------------------
            
        return jsonify({'success': False, 'message': 'Credenciales incorrectas'}), 401
        
    return render_template('login.html', logged_in=current_user.is_authenticated, current_user=current_user)



@app.route('/register', methods=['GET', 'POST'])
def register_page():
    if request.method == 'POST':
        data = request.get_json()
        if not data.get('cedula'):
            return jsonify({'success': False, 'message': 'La Cédula es obligatoria'}), 400
        if User.query.filter_by(username=data.get('username')).first():
            return jsonify({'success': False, 'message': 'Usuario ya existe'}), 409
        if User.query.filter_by(email=data.get('email')).first():
            return jsonify({'success': False, 'message': 'Email ya registrado'}), 409
        if User.query.filter_by(cedula=data.get('cedula')).first():
            return jsonify({'success': False, 'message': 'Cédula ya registrada'}), 409

        new_user = User(username=data.get('username'), email=data.get('email'), cedula=data.get('cedula'))
        new_user.set_password(data.get('password'))
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return jsonify({'success': True, 'redirect_url': url_for('index')})

    return render_template('register.html', logged_in=current_user.is_authenticated, current_user=current_user)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'GET':
        return render_template('forgot_password.html')
    
    data = request.get_json()
    email = data.get('email')
    user = User.query.filter_by(email=email).first()
    
    if user:
        # Generar contraseña temporal segura
        temp_pass = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
        user.set_password(temp_pass)
        db.session.commit()
        
        # Enviar correo
        try:
            msg = Message('Recuperación de Contraseña - Huellas al Corazón', recipients=[email])
            msg.body = f"""Hola {user.username},

Hemos recibido una solicitud para restablecer tu contraseña.

Tu nueva contraseña temporal es: {temp_pass}

Por favor inicia sesión con ella y recuerda que es una contraseña temporal.

Saludos,
El equipo de Huellas al Corazón
"""
            mail.send(msg)
            return jsonify({'success': True, 'message': 'Se ha enviado una nueva contraseña a tu correo.'})
        except Exception as e:
            return jsonify({'success': False, 'message': f'Error al enviar correo: {str(e)}'})
    
    return jsonify({'success': False, 'message': 'El correo no está registrado.'})

# --- RUTAS API PARA EL ADMIN (Mantenidas) ---

@app.route('/api/adopters', methods=['GET'])
@login_required
def get_adopters():
    """
    Obtiene la lista de perros adoptados cruzando datos de:
    User (Dueño), DogForAdoption (Perro), Adopter (Solicitud con detalles de contacto)
    """
    search = request.args.get('search_query', '')
    
    # Buscamos perros que ya tienen dueño (adoptados)
    query = db.session.query(DogForAdoption, User).join(
        User, DogForAdoption.owner_id == User.id
    ).filter(DogForAdoption.is_adopted == True)
    
    if search:
        query = query.filter(
            (User.cedula.ilike(f'%{search}%')) |
            (User.username.ilike(f'%{search}%')) |
            (DogForAdoption.name.ilike(f'%{search}%'))
        )
    
    adoptions = query.all()
    results = []
    
    for dog, user in adoptions:
        req = Adopter.query.filter_by(dog_id=dog.id, user_id=user.id, status='Aprobada').first()
        
        phone = req.phone if req else 'N/A'
        address = req.address if req else 'N/A'
        rif = req.rif if req else 'N/A'
        full_name = req.name if req else user.username

        # LÓGICA DE SEGUIMIENTO
        # Calculamos si tiene las fotos
        has_photo_1 = True if (dog.photo_adoption_day and dog.photo_adoption_day != '') else False
        has_photo_2 = True if (dog.photo_followup and dog.photo_followup != '') else False
        
        # Calculamos días desde la adopción para saber si está atrasado
        days_adopted = 0
        if dog.adoption_date:
            delta = datetime.now().date() - dog.adoption_date
            days_adopted = delta.days

        results.append({
            'id': req.id if req else dog.id,
            'dog_id': dog.id,
            'name': full_name,
            'user_name': user.username,
            'email': user.email,
            'phone': phone,
            'address': address,
            'cedula': user.cedula,
            'rif': rif,
            'pet_sex': dog.sex,
            'pet_status': dog.health_status,
            'adoption_date': dog.adoption_date.strftime('%Y-%m-%d') if dog.adoption_date else 'N/A',
            'full_dog_data': dog.to_dict(),
            # NUEVOS CAMPOS PARA EL ADMIN
            'has_photo_1': has_photo_1,
            'has_photo_2': has_photo_2,
            'photo_1_path': dog.photo_adoption_day, # <--- Ruta foto 1
            'photo_2_path': dog.photo_followup,     # <--- Ruta foto 2
            'days_adopted': days_adopted
        })
        
    return jsonify(results)

@app.route('/api/adopters', methods=['POST'])
@login_required
def add_adopter_api():
    """
    SOLUCIÓN PARA AGREGADO MANUAL:
    Crea un flujo completo simulado: Usuario -> Perro -> Solicitud Aprobada.
    """
    if current_user.username != 'gfiguera':
        return jsonify({'message': 'No autorizado'}), 403
        
    data = request.get_json()
    
    try:
        # 1. Buscar o Crear Usuario
        user = User.query.filter_by(cedula=data.get('cedula')).first()
        if not user:
            # Crear usuario dummy si no existe
            import random
            random_suffix = random.randint(1000, 9999)
            user = User(
                username=f"manual_{data.get('cedula')}", # Usuario temporal
                email=data.get('email'),
                cedula=data.get('cedula')
            )
            user.set_password(data.get('cedula')) # Contraseña es la cédula
            db.session.add(user)
            db.session.commit()
            
        # 2. Crear Perro (Asumiendo que es un registro histórico manual)
        new_dog = DogForAdoption(
            name="Registro Manual", # O podrías pedir el nombre del perro en el form
            sex=data.get('pet_sex', 'Desconocido'),
            age='Desconocida',
            photo_path='default_dog.png',
            health_status=data.get('pet_status', 'Sano'),
            is_adopted=True,
            owner_id=user.id,
            adoption_date=datetime.now().date()
        )
        db.session.add(new_dog)
        db.session.commit()
        
        # 3. Crear Solicitud Aprobada (Para mantener historial)
        req = Adopter(
            user_id=user.id,
            dog_id=new_dog.id,
            name=data.get('name'),
            phone=data.get('phone'),
            address=data.get('address'),
            rif=data.get('rif'),
            status='Aprobada'
        )
        db.session.add(req)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Adoptante registrado manualmente'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500
    


@app.route('/api/adopters/<int:id>', methods=['DELETE'])
@login_required
def manage_adopter(id):
    # Nota: El ID aquí puede ser el de la solicitud o un identificador lógico.
    # Para simplificar, borraremos la solicitud. El perro queda "adoptado" pero sin registro de solicitud.
    req = Adopter.query.get(id)
    if req:
        db.session.delete(req)
        db.session.commit()
        return jsonify({'message': 'Registro eliminado'})
    return jsonify({'message': 'No encontrado'}), 404


# --- API EVENTOS (Mantenida) ---
@app.route('/api/events', methods=['GET', 'POST'])
def api_events():
    if request.method == 'GET':
        events = Event.query.order_by(Event.date.asc()).all()
        return jsonify([e.to_dict() for e in events])
    if request.method == 'POST':
        if not current_user.is_authenticated or current_user.username != 'gfiguera':
            return jsonify({'message': 'Acceso denegado'}), 403
        try:
            file = request.files.get('photo')
            filename = None
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            new_event = Event(
                title=request.form['title'],
                date=datetime.strptime(request.form['date'], '%Y-%m-%d').date(),
                time=datetime.strptime(request.form['time'], '%H:%M').time(),
                end_time=datetime.strptime(request.form['end_time'], '%H:%M').time(),
                location=request.form.get('location'),
                description=request.form['description'],
                photo_path=filename
            )
            db.session.add(new_event)
            db.session.commit()
            return jsonify({'success': True, 'message': 'Evento creado'}), 201
        except Exception as e:
            return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/events/<int:id>', methods=['DELETE', 'PUT'])
@login_required
def manage_event(id):
    # 1. Verificar permisos
    if current_user.username != 'gfiguera':
        return jsonify({'message': 'Acceso denegado'}), 403
    
    event = Event.query.get_or_404(id)

    # --- OPCIÓN A: ELIMINAR ---
    if request.method == 'DELETE':
        try:
            # Borrar foto si existe
            if event.photo_path:
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], event.photo_path)
                if os.path.exists(file_path):
                    os.remove(file_path)
        except Exception as e:
            print(f"Error borrando imagen: {e}")

        db.session.delete(event)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Evento eliminado'})

    # --- OPCIÓN B: EDITAR (PUT) ---
    if request.method == 'PUT':
        data = request.get_json()
        try:
            event.title = data.get('title', event.title)
            event.location = data.get('location', event.location)
            event.description = data.get('description', event.description)
            
            # Parsear fechas y horas si vienen en el JSON
            if data.get('date'):
                event.date = datetime.strptime(data['date'], '%Y-%m-%d').date()
            if data.get('time'):
                event.time = datetime.strptime(data['time'], '%H:%M').time()
            if data.get('end_time'):
                event.end_time = datetime.strptime(data['end_time'], '%H:%M').time()

            db.session.commit()
            return jsonify({'success': True, 'message': 'Evento actualizado correctamente'})
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'message': f'Error al actualizar: {str(e)}'}), 500

# --- RUTA PARA CAMBIAR CONTRASEÑA (SIMPLIFICADA) ---
@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'GET':
        return render_template('change_password.html', 
                               logged_in=True, 
                               username=current_user.username, 
                               current_user=current_user)
    
    data = request.get_json()
    new_pass = data.get('new_password')
    
    if not new_pass:
        return jsonify({'success': False, 'message': 'La contraseña no puede estar vacía.'}), 400

    # ELIMINAMOS LA VERIFICACIÓN DE CLAVE ANTERIOR
    # Como el usuario ya está logueado (@login_required), asumimos que es él.
    
    current_user.set_password(new_pass)
    db.session.commit()
    
    return jsonify({'success': True, 'message': '¡Contraseña actualizada correctamente!'})

# --- GESTIÓN DE FOTOS DEL SITIO ---
@app.route('/upload_site_photo', methods=['POST'])
@login_required
def upload_site_photo():
    if current_user.username != 'gfiguera': return jsonify({'success': False}), 403
    
    section = request.form.get('section')
    file = request.files.get('photo')
    
    if file and allowed_file(file.filename):
        filename = secure_filename(f"site_{section}_{random.randint(1000,9999)}_{file.filename}")
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        
        # Si es del Grid (about_x), reemplazamos la existente
        if 'about' in section:
            existing = SitePhoto.query.filter_by(section=section).first()
            if existing:
                # Opcional: borrar archivo viejo del disco aquí
                existing.photo_path = filename
            else:
                new_photo = SitePhoto(section=section, photo_path=filename)
                db.session.add(new_photo)
        
        # Si es del Hero, agregamos una nueva a la lista
        elif section == 'hero':
            new_photo = SitePhoto(section='hero', photo_path=filename)
            db.session.add(new_photo)
            
        db.session.commit()
        return jsonify({'success': True, 'message': 'Foto actualizada'})
    
    return jsonify({'success': False, 'message': 'Error en archivo'}), 400

@app.route('/delete_site_photo/<int:id>', methods=['DELETE'])
@login_required
def delete_site_photo(id):
    if current_user.username != 'gfiguera': return jsonify({'success': False}), 403
    
    photo = SitePhoto.query.get_or_404(id)
    db.session.delete(photo)
    db.session.commit()
    return jsonify({'success': True, 'message': 'Foto eliminada'})

if __name__ == '__main__':
    with app.app_context():
        # --- ZONA DE MANTENIMIENTO ---
        # 1. Descomenta la siguiente línea UNA SOLA VEZ
        #    para borrar la base de datos y aplicar los nuevos cambios.
        # db.drop_all()
        
        # 2. Vuelve a comentar la línea de arriba y reinicia.
        db.create_all()
        
        # 3. Restaurar usuario admin
        if not User.query.filter_by(username='gfiguera').first():
            try:
                admin = User(username='gfiguera', email='admin@huellas.com', cedula='V-00000000') # Cédula de Admin
                admin.set_password('123456')
                db.session.add(admin)
                db.session.commit()
                print("Usuario admin 'gfiguera' restaurado.")
            except Exception as e:
                print(f"Error al crear admin (quizás la cédula V-00000000 ya existe): {e}")
                db.session.rollback()

    app.run(debug=True)