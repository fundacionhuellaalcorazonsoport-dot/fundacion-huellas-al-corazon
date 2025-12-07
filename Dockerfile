# -----------------------------------------------------------
# CAMBIO CRÍTICO: Actualizado a Python 3.10 para soportar click==8.2.1
FROM python:3.10-slim

# Establece el directorio de trabajo
WORKDIR /app

# Copia el archivo de requisitos e instala las dependencias
# (Asegúrate de que requirements.txt contenga gunicorn y psycopg2-binary)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copia el resto del código de tu aplicación (app.py, templates, static, etc.)
COPY . .

# Comando de ejecución de Gunicorn. Fly.io usa el puerto 8080 por defecto.
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "app:app"]
# -----------------------------------------------------------