# Usa una imagen base de Python (ajusta la versión si es necesario)
FROM python:3.9-slim

# Establece el directorio de trabajo
WORKDIR /app

# Copia el archivo de requisitos e instala las dependencias
# (Esto ya lo hiciste correctamente y usa tu archivo 'requirements.txt')
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copia el resto del código de tu aplicación (como app.py, templates, static, etc.)
# (Esta línea debe ir ANTES del comando de ejecución)
COPY . .

# Comando de ejecución (USA GUNICORN)
# Asegúrate de que tu aplicación principal en app.py se llama 'app'
CMD exec gunicorn --bind 0.0.0.0:"${PORT:-5000}" app:app