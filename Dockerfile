# Descripción: Archivo de configuración para la creación de la imagen de Docker
FROM python:3.9-slim

# Establece el directorio de trabajo en el contenedor
WORKDIR /app

# Copia los archivos necesarios para instalar las dependencias
COPY requirements.txt .
COPY MultiCompanyDataStorage.abi .
COPY app.py .

# Instala las dependencias
RUN pip install --no-cache-dir -r requirements.txt

# Copia el resto de los archivos de la aplicación al contenedor
COPY . .

# Exponer el puerto que la aplicación va a utilizar
EXPOSE 8081

# Comando para ejecutar la aplicación
CMD ["python", "app.py"]