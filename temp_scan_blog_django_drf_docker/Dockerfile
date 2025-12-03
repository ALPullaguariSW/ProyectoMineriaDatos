# Utiliza una imagen más específica de Python
FROM python:3.8-slim

# Establece el entorno para no almacenar en caché la salida estándar y estándar de error
ENV PYTHONUNBUFFERED 1

# Crea y establece el directorio de trabajo
WORKDIR /app

# Copia solo el archivo requirements.txt antes para aprovechar la caché de Docker
COPY requirements.txt /app/

# Instala las dependencias
RUN pip install --no-cache-dir -r requirements.txt

# Copia el resto de la aplicación al directorio de trabajo
COPY . /app/
