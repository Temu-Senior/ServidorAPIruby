# Wordguess API

API para el juego Wordguess (similar a Wordle). Desarrollada con Ruby (Sinatra), JWT para autenticación, SQLite como base de datos y Swagger UI para documentación interactiva.

## Requisitos

- Docker y Docker Compose (recomendado)
- Ruby 3.2+ (si se ejecuta localmente)

## Cómo levantar el proyecto con Docker

```bash
docker compose up --build
La API estará disponible en http://localhost:4567 y la documentación Swagger en http://localhost:4567/docs.

Autenticación
La API soporta dos métodos:

Cookie HttpOnly (para navegadores): se obtiene al hacer login.

Bearer Token (para clientes como curl o Postman): el token se devuelve en /login y debe enviarse en el header Authorization: Bearer <token>.

Obtener un token (ejemplo con curl)
bash
# 1. Registrar usuario
curl -X POST http://localhost:4567/register \
  -H "Content-Type: application/json" \
  -d '{"username": "jugador", "password": "123456"}'

# 2. Iniciar sesión (guarda el token de la respuesta)
curl -X POST http://localhost:4567/login \
  -H "Content-Type: application/json" \
  -d '{"username": "jugador", "password": "123456"}'
Respuesta de login:

json
{
  "success": true,
  "data": {
    "message": "login successful",
    "token": "eyJhbGciOiJIUzI1NiJ9..."
  }
}
Endpoints
Health
GET /health
Verifica el estado del servidor y la conexión a la base de datos.

Respuesta exitosa: 200 OK

json
{
  "success": true,
  "data": {
    "status": "ok",
    "db": "connected"
  }
}
Auth
POST /register
Registra un nuevo usuario.

Parámetros (JSON body):

username (string, requerido): 3-20 caracteres, solo letras, números y guion bajo.

password (string, requerido): mínimo 6 caracteres.

Ejemplo:

bash
curl -X POST http://localhost:4567/register \
  -H "Content-Type: application/json" \
  -d '{"username": "nuevo", "password": "secreta"}'
POST /login
Inicia sesión y devuelve un token JWT (en cookie HttpOnly y en el cuerpo).

Parámetros (JSON body):

username (string, requerido)

password (string, requerido)

POST /logout
Cierra la sesión actual, revoca el token y elimina las cookies. Requiere autenticación (Bearer o cookie).

Words
GET /words
Lista palabras. Filtros opcionales por fecha y dificultad.

Parámetros query:

date (string, opcional): formato YYYY-MM-DD.

difficulty (string, opcional): easy, medium o hard.

Ejemplo:

bash
curl "http://localhost:4567/words?date=2026-02-25&difficulty=hard"
POST /words
Crea una nueva palabra (solo administradores). Requiere autenticación Bearer.

Parámetros (JSON body):

text (string, requerido): la palabra.

difficulty (string, opcional): easy, medium, hard (por defecto medium).

date (string, opcional): formato YYYY-MM-DD.

Ejemplo:

bash
curl -X POST http://localhost:4567/words \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"text": "ruby", "difficulty": "medium", "date": "2026-02-27"}'
Games
POST /games
Inicia una nueva partida para el usuario autenticado. Requiere autenticación Bearer.

Parámetros (JSON body opcional):

date (string, opcional): fecha de la palabra a jugar (YYYY-MM-DD). Si no se envía, se elige una palabra al azar.

Ejemplo:

bash
curl -X POST http://localhost:4567/games \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"date": "2026-02-25"}'
GET /games/{id}
Obtiene el estado actual de una partida. Requiere autenticación Bearer.

Parámetros path:

id (integer, requerido): ID de la partida.

POST /games/{id}/attempts
Envía un intento (una palabra) para la partida especificada. Requiere autenticación Bearer.

Parámetros path:

id (integer, requerido): ID de la partida.

Parámetros (JSON body):

guess (string, requerido): la palabra que se intenta adivinar.

Ejemplo:

bash
curl -X POST http://localhost:4567/games/1/attempts \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"guess": "ruby"}'
User
GET /me/games
Obtiene el historial de partidas del usuario autenticado. Requiere autenticación Bearer.

Leaderboard
GET /leaderboard
Muestra los 20 mejores jugadores ordenados por victorias y promedio de intentos.

Desarrollo (solo en entorno development)
POST /_seed_demo
Carga palabras de ejemplo en la base de datos.

POST /make-me-admin
Convierte al usuario autenticado en administrador. Requiere autenticación Bearer.

Notas importantes
Los campos difficulty en las peticiones deben ir en minúsculas: easy, medium, hard.

El token JWT tiene una validez de 3 horas. Si expira, haz login nuevamente.

Los endpoints de desarrollo (/_seed_demo y /make-me-admin) solo están disponibles cuando RACK_ENV no es production.

Documentación interactiva
La API incluye Swagger UI en la ruta /docs. Allí puedes probar todos los endpoints directamente desde el navegador.

Desarrollado con Ruby, Sinatra y Docker.
