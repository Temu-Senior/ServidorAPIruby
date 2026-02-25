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
require 'rack/attack'

# ---------------- CONFIG ----------------
set :bind, '0.0.0.0'
set :port, ENV.fetch('PORT', 4567).to_i

DB_FILE = ENV.fetch('WORDGUESS_DB') { '/app/data/wordguess.db' }
DB = Sequel.sqlite(DB_FILE)

# JWT config
JWT_SECRET = ENV.fetch('WORDGUESS_JWT_SECRET', 'super_secreto_cambiar_en_produccion')
JWT_ALG = 'HS256'
JWT_EXP_SECONDS = (ENV.fetch('WORDGUESS_JWT_EXP_SECONDS', 3 * 3600).to_i) # default 3h

# BCrypt cost
BCOST = ENV.fetch('BCOST', '12').to_i

# CORS origins (comma separated)
# CORS origins - cambiado para desarrollo + Swagger
ALLOWED_ORIGINS = if ENV['RACK_ENV'] == 'production'
  ENV.fetch('CORS_ORIGINS', 'https://tu-dominio.com').split(',').map(&:strip)
else
  # En local: permite casi todo lo que usa Swagger y frontend común
  [
    'http://localhost:3000',
    'http://localhost:8080',     # Swagger más común
    'http://127.0.0.1:8080',
    'http://localhost:4567',     # mismo puerto del backend
    'http://127.0.0.1:4567',
    'http://localhost:5000',
    'http://localhost:3001',
    'http://localhost:4200'      # por si usas Angular u otro
  ].freeze
end

set :show_exceptions, false
set :raise_errors, false

# Fail fast if in production and secret is not configured
if ENV['RACK_ENV'] == 'production' && JWT_SECRET == 'super_secreto_cambiar_en_produccion'
  raise "JWT secret not configured in production! set WORDGUESS_JWT_SECRET"
end

# ---------------- RACK ATTACK (rate limiting) ----------------
# ---------------- RACK ATTACK (rate limiting) ----------------
class Rack::Attack
  # limit logins: 5 per minute per IP
  throttle('logins/ip', limit: 5, period: 60) do |req|
    req.ip if req.path == '/login' && req.post?
  end

  # limit attempts: 20 per minute per IP (guesses)
  throttle('attempts/ip', limit: 20, period: 60) do |req|
    req.ip if req.path =~ %r{^/games/\d+/attempts$} && req.post?
  end

  self.throttled_response = lambda do |env|
    [429, {'Content-Type' => 'application/json'}, [{ success: false, error: 'rate limit exceeded' }.to_json]]
  end
end

use Rack::Attack if ENV['RACK_ENV'] == 'production'

# ---------------- CORS ----------------
configure do
  enable :cross_origin
end

before do
  # default JSON response wrapper
  content_type :json

  origin = request.env['HTTP_ORIGIN']
  if origin && ALLOWED_ORIGINS.any?
    if ALLOWED_ORIGINS.include?(origin)
      response.headers['Access-Control-Allow-Origin'] = origin
      response.headers['Access-Control-Allow-Credentials'] = 'true'
    else
      # block unknown origins (prevents CSRF via cross-site requests with cookies)
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

  # Verify CSRF for mutating requests (double-submit)
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

# ---------------- SCHEMA ----------------
DB.create_table? :users do
  primary_key :id
  String :username, unique: true, null: false
  String :password_digest, null: false
  String :role, default: 'user'      # 'user' | 'admin'
  Integer :wins, default: 0
  Integer :losses, default: 0
  DateTime :created_at
end

# Migración para agregar columna role si no existe (para bases de datos existentes)
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

# table to store revoked JWT jti's (simple revocation list)
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

# ---------------- HELPERS / RESPONSES ----------------
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

  # Read JWT from HttpOnly cookie OR Authorization Bearer header.
  # Return user row or halt.
  def current_user!(halt_on_missing: true)
    token = nil
    # prefer Authorization Bearer (stateless clients)
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
      # check revocation
      if REVOKED.where(jti: decoded['jti']).first
        halt 401, render_error('token revoked')
      end
      user = USERS.where(id: decoded['user_id']).first
      halt 401, render_error('invalid user') unless user
      # Attach token metadata to env so other helpers can inspect if needed
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

  # CSRF verification (double-submit cookie)
  def verify_csrf_if_needed!
    # skip for safe methods
    return if %w[GET HEAD OPTIONS].include?(request.request_method)

    # Excluir rutas públicas que no necesitan CSRF
    public_paths = ['/register', '/login', '/health', '/_seed_demo', '/openapi.json', '/docs', '/logout']
    return if public_paths.include?(request.path)

    # if client sent Bearer auth, skip CSRF check (API clients)
    auth = request.env['HTTP_AUTHORIZATION']
    return if auth && auth.start_with?('Bearer ')

    # For cookie-based sessions: expect wg_csrf cookie and X-WG-CSRF header
    csrf_cookie = request.cookies['wg_csrf']
    csrf_header = request.env['HTTP_X_WG_CSRF'] || request.env['HTTP_X_CSRF_TOKEN']
    if csrf_cookie.nil? || csrf_header.nil?
      halt 403, render_error('csrf token missing', 403)
    end

    # secure compare to prevent timing attacks
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

# ---------------- ENDPOINTS ----------------

# Health
get '/health' do
  begin
    DB.test_connection
    render_success({ status: 'ok', db: 'connected' })
  rescue
    halt 500, render_error('db disconnected', 500)
  end
end

# Register
post '/register' do
  data = parse_json
  username = data['username']&.strip
  password = data['password']&.strip
  halt 400, render_error('username and password required') unless username && password && username != '' && password != ''

  # validations
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

# Login
post '/login' do
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
  jti = token_obj[:jti]

  # Cookie HttpOnly for JWT (browser will send it automatically)
  response.set_cookie('wg_token', value: token,
    httponly: true,
    secure: ENV['RACK_ENV'] == 'production',
    same_site: :lax,
    path: '/',
    max_age: JWT_EXP_SECONDS
  )

  # CSRF token (double-submit cookie) - readable by JS
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

# Refresh token (renew cookie) - accepts cookie or bearer
post '/refresh' do
  # require valid token first
  user = current_user!
  payload = request.env['wg.token_payload']
  # issue new token
  token_obj = generate_token(user[:id])
  token = token_obj[:token]

  response.set_cookie('wg_token', value: token,
    httponly: true,
    secure: ENV['RACK_ENV'] == 'production',
    same_site: :lax,
    path: '/',
    max_age: JWT_EXP_SECONDS
  )

  # rotate csrf cookie too (if cookie-based)
  unless request.env['wg.bearer_used']
    new_csrf = SecureRandom.hex(32)
    response.set_cookie('wg_csrf', value: new_csrf, httponly: false, secure: ENV['RACK_ENV'] == 'production', same_site: :lax, path: '/', max_age: JWT_EXP_SECONDS)
  end

  render_success({ message: 'token refreshed' })
end

# Logout
post '/logout' do
  # Try to revoke token server-side: read token payload
  begin
    payload = nil
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

  # delete cookies client-side
  response.delete_cookie('wg_token', path: '/')
  response.delete_cookie('wg_csrf', path: '/')
  render_success({ message: 'logged out' })
end

# Create a word (auth required, admin only)
post '/words' do
  user = current_user!
  halt 403, render_error('admin only') unless user_is_admin?(user)

  data = parse_json
  text = data['text']&.strip&.downcase
  difficulty = data['difficulty'] || 'medium'
  date = data['date']

  halt 400, render_error('text required') unless text && text != ''

  parsed_date = nil
  if date && !date.to_s.empty?
    parsed_date = begin
      Date.parse(date)
    rescue ArgumentError, TypeError
      nil
    end
    halt 400, render_error('invalid date format') unless parsed_date
  end

  id = WORDS.insert(text: text, difficulty: difficulty, date: parsed_date, created_at: Time.now)
  word = WORDS.where(id: id).first
  status 201
  render_success({ id: word[:id], text: word[:text], difficulty: word[:difficulty], date: word[:date] }, 201)
end

# List words (filter by date/difficulty) - public endpoint (returns full text)
get '/words' do
  q = WORDS
  if params['date']
    parsed_date = begin
      Date.parse(params['date'])
    rescue ArgumentError, TypeError
      nil
    end
    halt 400, render_error('invalid date format') unless parsed_date
    q = q.where(date: parsed_date)
  end
  q = q.where(difficulty: params['difficulty']) if params['difficulty']
  words = q.all.map { |w| { id: w[:id], text: w[:text], difficulty: w[:difficulty], date: w[:date] } }
  render_success({ words: words })
end

# Start a game for authenticated user
post '/games' do
  user = current_user!
  data = parse_json
  date = data['date']

  if date
    parsed_date = begin
      Date.parse(date)
    rescue ArgumentError, TypeError
      nil
    end
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

# Get game state
get '/games/:id' do |id|
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

# Submit an attempt
post '/games/:id/attempts' do |id|
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

# Get user's game history
get '/me/games' do
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

# Leaderboard
get '/leaderboard' do
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
    { id: r[:id], username: r[:username], wins: r[:wins], losses: r[:losses], avg_attempts_per_win: (r[:avg_attempts_per_win] && r[:avg_attempts_per_win].to_f) }
  end
  render_success({ leaderboard: data })
end

# Seed demo (dev only)
post '/_seed_demo' do
  halt 403, render_error('not allowed in production') if ENV['RACK_ENV'] == 'production'
  return render_success({ seed: 'already seeded' }) if WORDS.count > 0
  WORDS.insert(text: 'apple', difficulty: 'easy', date: Date.today - 1, created_at: Time.now)
  WORDS.insert(text: 'zebra', difficulty: 'medium', date: Date.today, created_at: Time.now)
  WORDS.insert(text: 'query', difficulty: 'hard', date: Date.today + 1, created_at: Time.now)
  render_success({ seed: 'ok' })
end

# Hacer admin al usuario actual (solo desarrollo)
post '/make-me-admin' do
  halt 403, render_error('not allowed in production') if ENV['RACK_ENV'] == 'production'
  user = current_user!
  USERS.where(id: user[:id]).update(role: 'admin')
  render_success({ message: 'now you are admin' })
end

# OpenAPI (unchanged structure)
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
            username: {
              type: 'string',
              example: 'angel',
              minLength: 3,
              maxLength: 20,
              pattern: '^[a-zA-Z0-9_]+$'
            },
            password: {
              type: 'string',
              example: 'secret123',
              minLength: 6,
              format: 'password'
            }
          }
        },
        LoginRequest: {
          type: 'object',
          required: ['username', 'password'],
          properties: {
            username: { type: 'string', example: 'angel' },
            password: { type: 'string', example: 'secret123', format: 'password' }
          }
        },
        Error: {
          type: 'object',
          properties: {
            success: { type: 'boolean', example: false },
            error: { type: 'string', example: 'mensaje de error' }
          }
        }
      }
    },
    paths: {
      '/health' => {
        get: {
          summary: 'Health check',
          responses: {
            '200' => {
              description: 'OK',
              content: { 'application/json' => { example: { status: 'ok', message: 'server running' } } }
            }
          }
        }
      },
      '/register' => {
        post: {
          summary: 'Register user',
          requestBody: {
            required: true,
            content: { 'application/json' => { schema: { '$ref' => '#/components/schemas/RegisterRequest' } } }
          },
          responses: {
            '201' => { description: 'Created', content: { 'application/json' => { example: { message: 'user created', id: 1, username: 'angel' } } } },
            '400' => { description: 'Bad Request' },
            '409' => { description: 'Conflict' }
          }
        }
      },
      '/login' => {
        post: {
          summary: 'Login user (sets HttpOnly cookie)',
          requestBody: {
            required: true,
            content: { 'application/json' => { schema: { '$ref' => '#/components/schemas/LoginRequest' } } }
          },
          responses: {
            '200' => { description: 'OK', content: { 'application/json' => { example: { message: 'login successful' } } } },
            '400' => { description: 'Bad Request' },
            '401' => { description: 'Unauthorized' }
          }
        }
      },
      '/logout' => {
        post: {
          summary: 'Logout user (deletes cookie)',
          responses: {
            '200' => { description: 'OK', content: { 'application/json' => { example: { message: 'logged out' } } } }
          }
        }
      },
      '/words' => {
        get: {
          summary: 'List words (optional filters: date, difficulty)',
          parameters: [
            { name: 'date', in: 'query', schema: { type: 'string', format: 'date' }, required: false },
            { name: 'difficulty', in: 'query', schema: { type: 'string' }, required: false }
          ],
          responses: { '200' => { description: 'OK' } }
        },
        post: {
          summary: 'Create a word (auth required)',
          security: [{ cookieAuth: [] }],
          requestBody: {
            required: true,
            content: {
              'application/json' => {
                schema: {
                  type: 'object',
                  properties: { text: { type: 'string' }, difficulty: { type: 'string' }, date: { type: 'string', format: 'date' } },
                  required: ['text']
                }
              }
            }
          },
          responses: {
            '201' => { description: 'Created' },
            '400' => { description: 'Bad Request' },
            '401' => { description: 'Unauthorized' }
          }
        }
      },
      '/games' => {
        post: {
          summary: 'Start game (auth required)',
          security: [{ bearerAuth: [] }],
          requestBody: {
            required: false,
            content: {
              'application/json' => {
                schema: { type: 'object', properties: { date: { type: 'string', format: 'date' } } }
              }
            }
          },
          responses: {
            '201' => { description: 'Game started' },
            '400' => { description: 'Bad Request' },
            '401' => { description: 'Unauthorized' },
            '404' => { description: 'Not Found' }
          }
        }
      },
      '/games/{id}' => {
        get: {
          summary: 'Get game state (auth required)',
          security: [{ bearerAuth: [] }],
          parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }],
          responses: {
            '200' => { description: 'OK' },
            '401' => { description: 'Unauthorized' },
            '404' => { description: 'Not Found' }
          }
        }
      },
      '/games/{id}/attempts' => {
        post: {
          summary: 'Submit attempt (auth required)',
          security: [{ bearerAuth: [] }],
          parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }],
          requestBody: {
            required: true,
            content: {
              'application/json' => {
                schema: { type: 'object', properties: { guess: { type: 'string' } }, required: ['guess'] }
              }
            }
          },
          responses: {
            '200' => { description: 'Attempt recorded' },
            '400' => { description: 'Bad Request' },
            '401' => { description: 'Unauthorized' },
            '404' => { description: 'Not Found' }
          }
        }
      },
      '/me/games' => {
        get: {
          summary: "Get authenticated user's game history",
          security: [{ bearerAuth: [] }],
          responses: { '200' => { description: 'OK' }, '401' => { description: 'Unauthorized' } }
        }
      },
      '/leaderboard' => {
        get: {
          summary: 'Leaderboard',
          responses: { '200' => { description: 'OK' } }
        }
      },
      '/_seed_demo' => {
        post: {
          summary: 'Seed demo data (dev only)',
          responses: { '200' => { description: 'OK' } }
        }
      }
    }
  }
  spec.to_json
end

# Swagger UI (docs)
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

# Static frontend serving (unchanged)
get '/' do
  send_file File.join(settings.root, 'frontend', 'index.html')
end

set :public_folder, File.join(settings.root, 'frontend')

# Run server (si se ejecuta el archivo directamente)
if __FILE__ == $0
  port = settings.port || ENV.fetch('PORT', 4567).to_i
  puts "Starting Wordguess Sinatra API on port #{port} -- DB: #{DB_FILE}"
  Sinatra::Application.run! port: port, bind: '0.0.0.0'
end