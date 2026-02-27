FROM ruby:3.2-slim

WORKDIR /app
COPY Gemfile* /app/

# Esto se ejecutará dentro del contenedor
FROM ruby:3.2-slim

WORKDIR /app

# Copiar archivos de dependencias primero (ahora se llaman Gemfile*)
COPY Gemfile* /app/
COPY Gemfile.lock* /app/

# Instalar dependencias del sistema y gemas
RUN apt-get update && \
    apt-get install -y build-essential libsqlite3-dev && \
    rm -rf /var/lib/apt/lists/* && \
    bundle install --jobs 4 --retry 3

# Copiar el resto del código
COPY . /app

EXPOSE 4567

CMD ["ruby", "WordguessSinatraApp.rb"]
