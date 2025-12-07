# init_db.py
from app import db, app # Ajusta esto según cómo defines 'db' y 'app' en tu app.py

with app.app_context():
    print("Creando todas las tablas...")
    db.create_all()
    print("Tablas creadas exitosamente.")