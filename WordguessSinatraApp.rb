# WordguessSinatraApp.rb
require 'sinatra'
require 'sinatra/cross_origin'
require 'sequel'
require 'json'
require 'bcrypt'
require 'jwt'
require 'time'
require 'date'
require 'securerandom'

# ---------------- CONFIG ----------------
set :bind, '0.0.0.0'
set :port, ENV.fetch('PORT', 4567).to_i

DB_FILE = ENV.fetch('WORDGUESS_DB') { '/tmp/wordguess.db' }
DB = Sequel.sqlite(DB_FILE)

# JWT config
JWT_SECRET = ENV.fetch('WORDGUESS_JWT_SECRET', 'super_secreto_cambiar_en_produccion')
JWT_ALG = 'HS256'
JWT_EXP_SECONDS = (ENV.fetch('WORDGUESS_JWT_EXP_SECONDS', 3 * 3600).to_i) # default 3h

# BCrypt cost
BCOST = ENV.fetch('BCOST', '12').to_i

# CORS origins
ALLOWED_ORIGINS = if ENV['RACK_ENV'] == 'production'
  ENV.fetch('CORS_ORIGINS', 'https://tu-dominio.com').split(',').map(&:strip)
else
  [
    'http://localhost:3000',
    'http://localhost:8080',
    'http://127.0.0.1:8080',
    'http://localhost:4567',
    'http://127.0.0.1:4567',
    'http://localhost:5000',
    'http://localhost:3001',
    'http://localhost:4200'
  ].freeze
end

set :show_exceptions, false
set :raise_errors, false

# Fail fast if in production and secret is not configured
if ENV['RACK_ENV'] == 'production' && JWT_SECRET == 'super_secreto_cambiar_en_produccion'
  raise "JWT secret not configured in production! set WORDGUESS_JWT_SECRET"
end

# ---------------- CORS ----------------
configure do
  enable :cross_origin
end

before do
  content_type :json

  origin = request.env['HTTP_ORIGIN']
  if origin && ALLOWED_ORIGINS.any?
    if ALLOWED_ORIGINS.include?(origin)
      response.headers['Access-Control-Allow-Origin'] = origin
      response.headers['Access-Control-Allow-Credentials'] = 'true'
    else
      halt 403, render_error('origin not allowed')
    end
  end

  response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Accept, X-WG-CSRF, Authorization'
  response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, PATCH, DELETE, OPTIONS'

  # Security headers
  response.headers['X-Content-Type-Options'] = 'nosniff'
  response.headers['X-Frame-Options'] = 'DENY'
  response.headers['Referrer-Policy'] = 'no-referrer'
  if ENV['RACK_ENV'] == 'production'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
  end

  verify_csrf_if_needed!
end

options '*' do
  origin = request.env['HTTP_ORIGIN']
  if origin && ALLOWED_ORIGINS.include?(origin)
    response.headers['Access-Control-Allow-Origin'] = origin
    response.headers['Access-Control-Allow-Credentials'] = 'true'
  end
  response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, PATCH, DELETE, OPTIONS'
  response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Accept, X-WG-CSRF, Authorization'
  200
end

# ---------------- HEALTH CHECK PARA RENDER ----------------
get '/health' do
  begin
    DB.test_connection
    { success: true, data: { status: 'ok', db: 'connected' } }.to_json
  rescue
    status 500
    { success: false, error: 'db disconnected' }.to_json
  end
end

# ---------------- SCHEMA ----------------
DB.create_table? :users do
  primary_key :id
  String :username, unique: true, null: false
  String :password_digest, null: false
  String :role, default: 'user'
  Integer :wins, default: 0
  Integer :losses, default: 0
  DateTime :created_at
end

if DB.table_exists?(:users) && !DB[:users].columns.include?(:role)
  DB.alter_table :users do
    add_column :role, String, default: 'user'
  end
end

DB.create_table? :words do
  primary_key :id
  String :text, null: false
  String :difficulty, null: false
  Date :date
  DateTime :created_at
end

DB.create_table? :games do
  primary_key :id
  foreign_key :user_id, :users
  foreign_key :word_id, :words
  Integer :attempts_allowed
  Integer :attempts_used, default: 0
  String :status, default: 'playing'
  DateTime :created_at
  DateTime :updated_at
end

DB.create_table? :attempts do
  primary_key :id
  foreign_key :game_id, :games
  String :guess
  Boolean :correct
  DateTime :created_at
end

DB.create_table? :revoked_tokens do
  primary_key :id
  String :jti, unique: true, null: false
  DateTime :revoked_at
end

USERS = DB[:users]
WORDS = DB[:words]
GAMES = DB[:games]
ATTEMPTS = DB[:attempts]
REVOKED = DB[:revoked_tokens]

# ---------------- HELPERS ----------------
helpers do
  def render_success(data = {}, status = 200)
    status status
    { success: true, data: data }.to_json
  end

  def render_error(message = 'error', status = 400)
    status status
    { success: false, error: message }.to_json
  end

  def parse_json
    request.body.rewind if request.body.respond_to?(:rewind)
    raw = request.body.read
    return {} if raw.nil? || raw.strip.empty?
    JSON.parse(raw)
  rescue JSON::ParserError
    halt 400, render_error('invalid json', 400)
  end

  def hash_password(p)
    BCrypt::Password.create(p, cost: BCOST)
  end

  def valid_password?(digest, plain)
    BCrypt::Password.new(digest) == plain
  end

  def generate_token(user_id)
    jti = SecureRandom.uuid
    payload = {
      user_id: user_id,
      exp: (Time.now + JWT_EXP_SECONDS).to_i,
      iat: Time.now.to_i,
      jti: jti
    }
    token = JWT.encode(payload, JWT_SECRET, JWT_ALG)
    { token: token, jti: jti }
  end

  def current_user!(halt_on_missing: true)
    token = nil
    auth = request.env['HTTP_AUTHORIZATION']
    if auth && auth.start_with?('Bearer ')
      token = auth.split(' ', 2)[1]
      bearer_used = true
    else
      token = request.cookies['wg_token']
      bearer_used = false
    end

    if token.nil? || token.strip.empty?
      halt 401, render_error('missing token') if halt_on_missing
      return nil
    end

    begin
      decoded = JWT.decode(token, JWT_SECRET, true, algorithm: JWT_ALG)[0]
      if REVOKED.where(jti: decoded['jti']).first
        halt 401, render_error('token revoked')
      end
      user = USERS.where(id: decoded['user_id']).first
      halt 401, render_error('invalid user') unless user
      request.env['wg.token_payload'] = decoded
      request.env['wg.bearer_used'] = bearer_used
      user
    rescue JWT::ExpiredSignature
      halt 401, render_error('token expired')
    rescue JWT::DecodeError
      halt 401, render_error('invalid token')
    end
  end

  def attempts_for_difficulty(diff)
    case diff.to_s.downcase
    when 'easy' then 8
    when 'medium' then 6
    when 'hard' then 4
    else 6
    end
  end

  def match_feedback(word, guess)
    word_s = word.chars
    guess_s = guess.chars
    positions = guess_s.each_with_index.map { |ch, i| ch == word_s[i] }
    letter_matches = guess_s.uniq.count { |ch| word_s.include?(ch) }
    {
      correct: guess == word,
      positions: positions,
      letter_matches_count: letter_matches
    }
  end

  def user_is_admin?(user)
    user && user[:role] == 'admin'
  end

  def verify_csrf_if_needed!
  return if %w[GET HEAD OPTIONS].include?(request.request_method)
  public_paths = [
    '/api/v1/register', 
    '/api/v1/login', 
    '/api/v1/health',
    '/api/v1/_seed_demo', 
    '/api/v1/logout', 
    '/api/v1/make-me-admin-secret',  # <-- AÑADE ESTA LÍNEA
    '/openapi.json', 
    '/docs'
  ]
    return if public_paths.include?(request.path)

    auth = request.env['HTTP_AUTHORIZATION']
    return if auth && auth.start_with?('Bearer ')

    csrf_cookie = request.cookies['wg_csrf']
    csrf_header = request.env['HTTP_X_WG_CSRF'] || request.env['HTTP_X_CSRF_TOKEN']
    if csrf_cookie.nil? || csrf_header.nil?
      halt 403, render_error('csrf token missing', 403)
    end
    unless Rack::Utils.secure_compare(csrf_cookie, csrf_header)
      halt 403, render_error('invalid csrf token', 403)
    end
  end
end

# ---------------- ERRORS ----------------
error do
  e = env['sinatra.error']
  status 500
  { success: false, error: 'internal server error', message: e&.message }.to_json
end

not_found do
  render_error('not found', 404)
end

# ---------------- ENDPOINTS (versionados bajo /api/v1) ----------------

get '/api/v1/health' do
  begin
    DB.test_connection
    render_success({ status: 'ok', db: 'connected' })
  rescue
    halt 500, render_error('db disconnected', 500)
  end
end

post '/api/v1/register' do
  data = parse_json
  username = data['username']&.strip
  password = data['password']&.strip
  halt 400, render_error('username and password required') unless username && password && username != '' && password != ''

  unless username =~ /\A[a-zA-Z0-9_]{3,20}\z/
    halt 400, render_error('invalid username format (3-20 alnum/_)')
  end
  unless password.length >= 6
    halt 400, render_error('password too short (min 6)')
  end

  if USERS.where(username: username).first
    halt 409, render_error('username taken', 409)
  end

  id = USERS.insert(username: username, password_digest: hash_password(password), role: 'user', created_at: Time.now)
  user = USERS.where(id: id).first
  status 201
  render_success({ id: user[:id], username: user[:username] }, 201)
end

post '/api/v1/login' do
  data = parse_json
  username = data['username']
  password = data['password']
  halt 400, render_error('username and password required') unless username && password

  user = USERS.where(username: username).first
  unless user && valid_password?(user[:password_digest], password)
    halt 401, render_error('invalid credentials', 401)
  end

  token_obj = generate_token(user[:id])
  token = token_obj[:token]

  response.set_cookie('wg_token', value: token,
    httponly: true,
    secure: ENV['RACK_ENV'] == 'production',
    same_site: :lax,
    path: '/',
    max_age: JWT_EXP_SECONDS
  )

  csrf = SecureRandom.hex(32)
  response.set_cookie('wg_csrf', value: csrf,
    httponly: false,
    secure: ENV['RACK_ENV'] == 'production',
    same_site: :lax,
    path: '/',
    max_age: JWT_EXP_SECONDS
  )

  render_success({ message: 'login successful', token: token })
end

post '/api/v1/refresh' do
  user = current_user!
  token_obj = generate_token(user[:id])
  token = token_obj[:token]

  response.set_cookie('wg_token', value: token,
    httponly: true,
    secure: ENV['RACK_ENV'] == 'production',
    same_site: :lax,
    path: '/',
    max_age: JWT_EXP_SECONDS
  )

  unless request.env['wg.bearer_used']
    new_csrf = SecureRandom.hex(32)
    response.set_cookie('wg_csrf', value: new_csrf, httponly: false, secure: ENV['RACK_ENV'] == 'production', same_site: :lax, path: '/', max_age: JWT_EXP_SECONDS)
  end

  render_success({ message: 'token refreshed' })
end

post '/api/v1/logout' do
  begin
    auth = request.env['HTTP_AUTHORIZATION']
    if auth && auth.start_with?('Bearer ')
      token = auth.split(' ', 2)[1]
    else
      token = request.cookies['wg_token']
    end

    if token && !token.strip.empty?
      decoded = JWT.decode(token, JWT_SECRET, true, algorithm: JWT_ALG)[0]
      REVOKED.insert(jti: decoded['jti'], revoked_at: Time.now) rescue nil
    end
  rescue
    # ignore decode errors on logout
  end

  response.delete_cookie('wg_token', path: '/')
  response.delete_cookie('wg_csrf', path: '/')
  render_success({ message: 'logged out' })
end

post '/api/v1/words' do
  user = current_user!
  halt 403, render_error('admin only') unless user_is_admin?(user)

  data = parse_json
  text = data['text']&.strip&.downcase
  difficulty = data['difficulty'] || 'medium'
  date = data['date']

  halt 400, render_error('text required') unless text && text != ''

  parsed_date = nil
  if date && !date.to_s.empty?
    parsed_date = Date.parse(date) rescue nil
    halt 400, render_error('invalid date format') unless parsed_date
  end

  id = WORDS.insert(text: text, difficulty: difficulty, date: parsed_date, created_at: Time.now)
  word = WORDS.where(id: id).first
  status 201
  render_success({ id: word[:id], text: word[:text], difficulty: word[:difficulty], date: word[:date] }, 201)
end

get '/api/v1/words' do
  q = WORDS
  if params['date']
    parsed_date = Date.parse(params['date']) rescue nil
    halt 400, render_error('invalid date format') unless parsed_date
    q = q.where(date: parsed_date)
  end
  q = q.where(difficulty: params['difficulty']) if params['difficulty']
  words = q.all.map { |w| { id: w[:id], text: w[:text], difficulty: w[:difficulty], date: w[:date] } }
  render_success({ words: words })
end

post '/api/v1/games' do
  user = current_user!
  data = parse_json
  date = data['date']

  if date
    parsed_date = Date.parse(date) rescue nil
    halt 400, render_error('invalid date format') unless parsed_date
    word_row = WORDS.where(date: parsed_date).first
    halt 404, render_error('no word for that date') unless word_row
  else
    word_row = WORDS.order(Sequel.lit('RANDOM()')).first
    halt 404, render_error('no words yet') unless word_row
  end

  attempts_allowed = attempts_for_difficulty(word_row[:difficulty])
  gid = GAMES.insert(user_id: user[:id], word_id: word_row[:id], attempts_allowed: attempts_allowed, attempts_used: 0, status: 'playing', created_at: Time.now, updated_at: Time.now)
  game = GAMES.where(id: gid).first
  status 201
  render_success({ id: game[:id], attempts_allowed: game[:attempts_allowed], status: game[:status], word_length: word_row[:text].length }, 201)
end

get '/api/v1/games/:id' do |id|
  user = current_user!
  game = GAMES.where(id: id, user_id: user[:id]).first
  halt 404, render_error('game not found') unless game
  attempts = ATTEMPTS.where(game_id: game[:id]).all.map { |a| { id: a[:id], guess: a[:guess], correct: a[:correct], created_at: a[:created_at] } }
  word = WORDS.where(id: game[:word_id]).first
  render_success({
    id: game[:id],
    attempts_allowed: game[:attempts_allowed],
    attempts_used: game[:attempts_used],
    status: game[:status],
    attempts: attempts,
    word_length: word[:text].length
  })
end

post '/api/v1/games/:id/attempts' do |id|
  user = current_user!
  game = GAMES.where(id: id, user_id: user[:id]).first
  halt 404, render_error('game not found') unless game
  halt 400, render_error('game already finished') if %w[won lost].include?(game[:status])

  data = parse_json
  guess = data['guess']&.strip&.downcase
  halt 400, render_error('guess required') unless guess

  word = WORDS.where(id: game[:word_id]).first
  feedback = match_feedback(word[:text], guess)
  correct = feedback[:correct]

  ATTEMPTS.insert(game_id: game[:id], guess: guess, correct: correct, created_at: Time.now)
  new_attempts_used = game[:attempts_used] + 1
  new_status = 'playing'
  if correct
    new_status = 'won'
    USERS.where(id: user[:id]).update(wins: Sequel[:wins] + 1)
  elsif new_attempts_used >= game[:attempts_allowed]
    new_status = 'lost'
    USERS.where(id: user[:id]).update(losses: Sequel[:losses] + 1)
  end

  GAMES.where(id: game[:id]).update(attempts_used: new_attempts_used, status: new_status, updated_at: Time.now)

  render_success({ message: 'attempt recorded', correct: correct, status: new_status, feedback: feedback })
end

get '/api/v1/me/games' do
  user = current_user!
  games = GAMES.where(user_id: user[:id]).order(Sequel.desc(:created_at)).all.map do |g|
    w = WORDS.where(id: g[:word_id]).first
    {
      id: g[:id],
      status: g[:status],
      attempts_allowed: g[:attempts_allowed],
      attempts_used: g[:attempts_used],
      word_length: w[:text].length,
      created_at: g[:created_at]
    }
  end
  render_success({ games: games })
end

get '/api/v1/leaderboard' do
  rows = DB.fetch(<<~SQL)
    SELECT u.id, u.username, u.wins, u.losses,
      (SELECT AVG(a_count) FROM (
        SELECT COUNT(*) as a_count FROM attempts a
        JOIN games g ON g.id = a.game_id
        WHERE g.user_id = u.id AND g.status = 'won'
        GROUP BY g.id
      )) as avg_attempts_per_win
    FROM users u
    ORDER BY u.wins DESC, avg_attempts_per_win ASC NULLS LAST
    LIMIT 20
  SQL

  data = rows.map do |r|
    { id: r[:id], username: r[:username], wins: r[:wins], losses: r[:losses], avg_attempts_per_win: r[:avg_attempts_per_win]&.to_f }
  end
  render_success({ leaderboard: data })
end

post '/api/v1/_seed_demo' do
  halt 403, render_error('not allowed in production') if ENV['RACK_ENV'] == 'production'
  return render_success({ seed: 'already seeded' }) if WORDS.count > 0
  WORDS.insert(text: 'apple', difficulty: 'easy', date: Date.today - 1, created_at: Time.now)
  WORDS.insert(text: 'zebra', difficulty: 'medium', date: Date.today, created_at: Time.now)
  WORDS.insert(text: 'query', difficulty: 'hard', date: Date.today + 1, created_at: Time.now)
  render_success({ seed: 'ok' })
end

post '/api/v1/make-me-admin' do
  halt 403, render_error('not allowed in production') if ENV['RACK_ENV'] == 'production'
  user = current_user!
  USERS.where(id: user[:id]).update(role: 'admin')
  render_success({ message: 'now you are admin' })
end

# ---------------- OPENAPI ----------------
get '/openapi.json' do
  spec = {
    openapi: '3.0.1',
    info: {
      title: 'Wordguess API',
      version: '1.0.0',
      description: 'Wordguess API (Sinatra) con JWT almacenado en cookie HttpOnly (soporta cookie y bearer)'
    },
    servers: [{ url: request.base_url }],
    components: {
      securitySchemes: {
        cookieAuth: { type: 'apiKey', in: 'cookie', name: 'wg_token' },
        bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' }
      },
      schemas: {
        RegisterRequest: {
          type: 'object',
          required: ['username', 'password'],
          properties: {
            username: { type: 'string', description: 'Nombre de usuario. Solo letras, números y guion bajo. Longitud 3-20.', example: 'angel', minLength: 3, maxLength: 20, pattern: '^[a-zA-Z0-9_]+$' },
            password: { type: 'string', description: 'Contraseña. Mínimo 6 caracteres.', example: 'secret123', minLength: 6, format: 'password' }
          }
        },
        LoginRequest: {
          type: 'object',
          required: ['username', 'password'],
          properties: {
            username: { type: 'string', description: 'Nombre de usuario registrado.', example: 'angel' },
            password: { type: 'string', description: 'Contraseña del usuario.', example: 'secret123', format: 'password' }
          }
        },
        Error: {
          type: 'object',
          properties: {
            success: { type: 'boolean', example: false },
            error: { type: 'string', example: 'mensaje de error' }
          }
        },
        Word: {
          type: 'object',
          properties: {
            id: { type: 'integer', description: 'ID único de la palabra' },
            text: { type: 'string', description: 'La palabra' },
            difficulty: { type: 'string', enum: ['easy', 'medium', 'hard'], description: 'Dificultad' },
            date: { type: 'string', format: 'date', description: 'Fecha asociada a la palabra' }
          }
        },
        Game: {
          type: 'object',
          properties: {
            id: { type: 'integer', description: 'ID de la partida' },
            attempts_allowed: { type: 'integer', description: 'Número máximo de intentos permitidos' },
            attempts_used: { type: 'integer', description: 'Intentos realizados' },
            status: { type: 'string', enum: ['playing', 'won', 'lost'], description: 'Estado de la partida' },
            word_length: { type: 'integer', description: 'Longitud de la palabra a adivinar' },
            created_at: { type: 'string', format: 'date-time', description: 'Fecha de creación' }
          }
        },
        Attempt: {
          type: 'object',
          properties: {
            id: { type: 'integer', description: 'ID del intento' },
            guess: { type: 'string', description: 'Palabra intentada' },
            correct: { type: 'boolean', description: 'Si el intento fue correcto' },
            created_at: { type: 'string', format: 'date-time', description: 'Momento del intento' }
          }
        }
      }
    },
    paths: {
      '/api/v1/health' => {
        get: {
          tags: ['Status'],
          summary: 'Health check',
          description: 'Verifica que el servidor y la base de datos estén funcionando.',
          responses: {
            '200' => {
              description: 'Servidor OK',
              content: {
                'application/json' => {
                  example: { success: true, data: { status: 'ok', db: 'connected' } }
                }
              }
            },
            '500' => {
              description: 'Error de conexión con la base de datos',
              content: { 'application/json' => { schema: { '$ref' => '#/components/schemas/Error' } } }
            }
          }
        }
      },
      '/api/v1/register' => {
        post: {
          tags: ['Auth'],
          summary: 'Register user',
          description: 'Crea una nueva cuenta de usuario.',
          requestBody: {
            required: true,
            content: {
              'application/json' => {
                schema: { '$ref' => '#/components/schemas/RegisterRequest' }
              }
            }
          },
          responses: {
            '201' => {
              description: 'Usuario creado exitosamente',
              content: {
                'application/json' => {
                  schema: {
                    type: 'object',
                    properties: {
                      success: { type: 'boolean', example: true },
                      data: {
                        type: 'object',
                        properties: {
                          id: { type: 'integer', description: 'ID del nuevo usuario' },
                          username: { type: 'string', description: 'Nombre de usuario' }
                        }
                      }
                    }
                  },
                  example: { success: true, data: { id: 1, username: 'angel' } }
                }
              }
            },
            '400' => {
              description: 'Datos inválidos (formato de usuario o contraseña incorrectos)',
              content: { 'application/json' => { schema: { '$ref' => '#/components/schemas/Error' } } }
            },
            '409' => {
              description: 'El nombre de usuario ya existe',
              content: { 'application/json' => { schema: { '$ref' => '#/components/schemas/Error' } } }
            }
          }
        }
      },
      '/api/v1/login' => {
        post: {
          tags: ['Auth'],
          summary: 'Login user',
          description: 'Inicia sesión y devuelve un token JWT (en cookie HttpOnly y en el cuerpo).',
          requestBody: {
            required: true,
            content: {
              'application/json' => {
                schema: { '$ref' => '#/components/schemas/LoginRequest' }
              }
            }
          },
          responses: {
            '200' => {
              description: 'Login exitoso',
              content: {
                'application/json' => {
                  schema: {
                    type: 'object',
                    properties: {
                      success: { type: 'boolean', example: true },
                      data: {
                        type: 'object',
                        properties: {
                          message: { type: 'string', example: 'login successful' },
                          token: { type: 'string', description: 'Token JWT para usar en Bearer Auth' }
                        }
                      }
                    }
                  }
                }
              }
            },
            '400' => {
              description: 'Faltan credenciales',
              content: { 'application/json' => { schema: { '$ref' => '#/components/schemas/Error' } } }
            },
            '401' => {
              description: 'Credenciales inválidas',
              content: { 'application/json' => { schema: { '$ref' => '#/components/schemas/Error' } } }
            }
          }
        }
      },
      '/api/v1/logout' => {
        post: {
          tags: ['Auth'],
          summary: 'Logout user',
          description: 'Cierra la sesión actual, revoca el token y elimina las cookies.',
          security: [{ bearerAuth: [] }, { cookieAuth: [] }],
          responses: {
            '200' => {
              description: 'Logout exitoso',
              content: {
                'application/json' => {
                  example: { success: true, data: { message: 'logged out' } }
                }
              }
            }
          }
        }
      },
      '/api/v1/words' => {
        get: {
          tags: ['Words'],
          summary: 'List words',
          description: 'Obtiene lista de palabras. Opcionalmente filtra por fecha y/o dificultad.',
          parameters: [
            { name: 'date', in: 'query', required: false, schema: { type: 'string', format: 'date' }, description: 'Fecha en formato YYYY-MM-DD.' },
            { name: 'difficulty', in: 'query', required: false, schema: { type: 'string', enum: ['easy', 'medium', 'hard'] }, description: 'Dificultad de la palabra.' }
          ],
          responses: {
            '200' => {
              description: 'Lista de palabras',
              content: {
                'application/json' => {
                  schema: {
                    type: 'object',
                    properties: {
                      success: { type: 'boolean' },
                      data: {
                        type: 'object',
                        properties: {
                          words: { type: 'array', items: { '$ref' => '#/components/schemas/Word' } }
                        }
                      }
                    }
                  }
                }
              }
            },
            '400' => { description: 'Formato de fecha inválido', content: { 'application/json' => { schema: { '$ref' => '#/components/schemas/Error' } } } }
          }
        },
        post: {
          tags: ['Words'],
          summary: 'Create a word',
          description: 'Crea una nueva palabra (solo para administradores).',
          security: [{ bearerAuth: [] }],
          requestBody: {
            required: true,
            content: {
              'application/json' => {
                schema: {
                  type: 'object',
                  required: ['text'],
                  properties: {
                    text: { type: 'string', description: 'La palabra a agregar.' },
                    difficulty: { type: 'string', enum: ['easy', 'medium', 'hard'], default: 'medium' },
                    date: { type: 'string', format: 'date', description: 'Fecha asociada (opcional).' }
                  }
                }
              }
            }
          },
          responses: {
            '201' => { description: 'Palabra creada', content: { 'application/json' => { schema: { type: 'object', properties: { success: { type: 'boolean' }, data: { '$ref' => '#/components/schemas/Word' } } } } } },
            '400' => { description: 'Texto requerido o fecha inválida', content: { 'application/json' => { schema: { '$ref' => '#/components/schemas/Error' } } } },
            '401' => { description: 'No autenticado', content: { 'application/json' => { schema: { '$ref' => '#/components/schemas/Error' } } } },
            '403' => { description: 'Requiere rol de administrador', content: { 'application/json' => { schema: { '$ref' => '#/components/schemas/Error' } } } }
          }
        }
      },
      '/api/v1/games' => {
        post: {
          tags: ['Games'],
          summary: 'Start a new game',
          description: 'Inicia una nueva partida para el usuario autenticado.',
          security: [{ bearerAuth: [] }],
          requestBody: {
            required: false,
            content: {
              'application/json' => {
                schema: {
                  type: 'object',
                  properties: {
                    date: { type: 'string', format: 'date', description: 'Fecha de la palabra a jugar.' }
                  }
                }
              }
            }
          },
          responses: {
            '201' => { description: 'Partida creada', content: { 'application/json' => { schema: { type: 'object', properties: { success: { type: 'boolean' }, data: { '$ref' => '#/components/schemas/Game' } } } } } },
            '400' => { description: 'Formato de fecha inválido', content: { 'application/json' => { schema: { '$ref' => '#/components/schemas/Error' } } } },
            '401' => { description: 'No autenticado', content: { 'application/json' => { schema: { '$ref' => '#/components/schemas/Error' } } } },
            '404' => { description: 'No hay palabra para la fecha o no hay palabras', content: { 'application/json' => { schema: { '$ref' => '#/components/schemas/Error' } } } }
          }
        }
      },
      '/api/v1/games/{id}' => {
        get: {
          tags: ['Games'],
          summary: 'Get game state',
          description: 'Obtiene el estado actual de una partida.',
          security: [{ bearerAuth: [] }],
          parameters: [ { name: 'id', in: 'path', required: true, schema: { type: 'integer' }, description: 'ID de la partida' } ],
          responses: {
            '200' => {
              description: 'Estado de la partida',
              content: {
                'application/json' => {
                  schema: {
                    type: 'object',
                    properties: {
                      success: { type: 'boolean' },
                      data: {
                        allOf: [
                          { '$ref' => '#/components/schemas/Game' },
                          { type: 'object', properties: { attempts: { type: 'array', items: { '$ref' => '#/components/schemas/Attempt' } } } }
                        ]
                      }
                    }
                  }
                }
              }
            },
            '401' => { description: 'No autenticado', content: { 'application/json' => { schema: { '$ref' => '#/components/schemas/Error' } } } },
            '404' => { description: 'Partida no encontrada', content: { 'application/json' => { schema: { '$ref' => '#/components/schemas/Error' } } } }
          }
        }
      },
      '/api/v1/games/{id}/attempts' => {
        post: {
          tags: ['Games'],
          summary: 'Submit an attempt',
          description: 'Envía un intento para la partida.',
          security: [{ bearerAuth: [] }],
          parameters: [ { name: 'id', in: 'path', required: true, schema: { type: 'integer' }, description: 'ID de la partida' } ],
          requestBody: {
            required: true,
            content: {
              'application/json' => {
                schema: {
                  type: 'object',
                  required: ['guess'],
                  properties: { guess: { type: 'string', description: 'Palabra intentada.' } }
                }
              }
            }
          },
          responses: {
            '200' => {
              description: 'Intento registrado',
              content: {
                'application/json' => {
                  schema: {
                    type: 'object',
                    properties: {
                      success: { type: 'boolean' },
                      data: {
                        type: 'object',
                        properties: {
                          message: { type: 'string' },
                          correct: { type: 'boolean' },
                          status: { type: 'string', enum: ['playing', 'won', 'lost'] },
                          feedback: {
                            type: 'object',
                            properties: {
                              positions: { type: 'array', items: { type: 'boolean' } },
                              letter_matches_count: { type: 'integer' }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            },
            '400' => { description: 'Falta guess o partida terminada', content: { 'application/json' => { schema: { '$ref' => '#/components/schemas/Error' } } } },
            '401' => { description: 'No autenticado', content: { 'application/json' => { schema: { '$ref' => '#/components/schemas/Error' } } } },
            '404' => { description: 'Partida no encontrada', content: { 'application/json' => { schema: { '$ref' => '#/components/schemas/Error' } } } }
          }
        }
      },
      '/api/v1/me/games' => {
        get: {
          tags: ['User'],
          summary: "User's game history",
          description: 'Historial de partidas del usuario autenticado.',
          security: [{ bearerAuth: [] }],
          responses: {
            '200' => {
              description: 'Historial',
              content: {
                'application/json' => {
                  schema: {
                    type: 'object',
                    properties: {
                      success: { type: 'boolean' },
                      data: {
                        type: 'object',
                        properties: {
                          games: { type: 'array', items: { '$ref' => '#/components/schemas/Game' } }
                        }
                      }
                    }
                  }
                }
              }
            },
            '401' => { description: 'No autenticado', content: { 'application/json' => { schema: { '$ref' => '#/components/schemas/Error' } } } }
          }
        }
      },
      '/api/v1/leaderboard' => {
        get: {
          tags: ['Leaderboard'],
          summary: 'Leaderboard',
          description: 'Ranking de jugadores.',
          responses: {
            '200' => {
              description: 'Ranking',
              content: {
                'application/json' => {
                  example: {
                    success: true,
                    data: {
                      leaderboard: [ { id: 1, username: 'angel', wins: 10, losses: 2, avg_attempts_per_win: 4.5 } ]
                    }
                  }
                }
              }
            }
          }
        }
      },
      '/api/v1/_seed_demo' => {
        post: {
          tags: ['Development'],
          summary: 'Seed demo data',
          description: 'Carga palabras de ejemplo (solo desarrollo).',
          responses: {
            '200' => { description: 'OK', content: { 'application/json' => { example: { success: true, data: { seed: 'ok' } } } } },
            '403' => { description: 'No permitido en producción', content: { 'application/json' => { schema: { '$ref' => '#/components/schemas/Error' } } } }
          }
        }
      },
      '/api/v1/make-me-admin' => {
        post: {
          tags: ['Development'],
          summary: 'Make current user admin',
          description: 'Convierte al usuario en admin (solo desarrollo).',
          security: [{ bearerAuth: [] }],
          responses: {
            '200' => { description: 'OK', content: { 'application/json' => { example: { success: true, data: { message: 'now you are admin' } } } } },
            '401' => { description: 'No autenticado', content: { 'application/json' => { schema: { '$ref' => '#/components/schemas/Error' } } } },
            '403' => { description: 'No permitido en producción', content: { 'application/json' => { schema: { '$ref' => '#/components/schemas/Error' } } } }
          }
        }
      }
    }
  }
  spec.to_json
end

# ---------------- SWAGGER UI ----------------
get '/docs' do
  content_type 'text/html'
  <<~HTML
  <!doctype html>
  <html>
  <head>
    <meta charset="utf-8" />
    <title>Wordguess API Docs</title>
    <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist/swagger-ui.css" />
    <style>body{margin:0;padding:0}</style>
  </head>
  <body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist/swagger-ui-bundle.js"></script>
    <script>
      SwaggerUIBundle({ url: '/openapi.json', dom_id: '#swagger-ui' });
    </script>
  </body>
  </html>
  HTML
end

# Hacer admin al usuario actual (requiere clave secreta incluso en producción)
post '/api/v1/make-me-admin' do
  admin_key = request.env['HTTP_X_ADMIN_KEY']
  if admin_key != ENV.fetch('ADMIN_SECRET', 'no_secret')
    halt 403, render_error('not allowed')
  end

  user = current_user!
  USERS.where(id: user[:id]).update(role: 'admin')
  render_success({ message: 'now you are admin' })
end

# ---------------- SERVE FRONTEND ----------------
get '/' do
  content_type 'text/html'
  begin
    html = File.read(File.join(settings.root, 'frontend', 'index.html'))
    html.gsub!("const API_BASE = 'http://127.0.0.1:4567';", "const API_BASE = '/api/v1';")
    html
  rescue Errno::ENOENT
    "<h1>Wordguess API</h1><p>Frontend no encontrado. La API está disponible en <a href='/docs'>/docs</a>.</p>"
  end
end

set :public_folder, File.join(settings.root, 'frontend')

if __FILE__ == $0
  port = settings.port || ENV.fetch('PORT', 4567).to_i
  puts "Starting Wordguess Sinatra API on port #{port} -- DB: #{DB_FILE}"
  puts "API endpoints disponibles bajo /api/v1"
  Sinatra::Application.run! port: port, bind: '0.0.0.0'
end
