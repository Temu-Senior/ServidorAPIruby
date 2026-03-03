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

# Mejor usar /tmp/ para SQLite en Render (sistema de archivos efímero pero escribible)
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
    'http://localhost:3000', 'http://localhost:8080', 'http://127.0.0.1:8080',
    'http://localhost:4567', 'http://127.0.0.1:4567', 'http://localhost:5000',
    'http://localhost:3001', 'http://localhost:4200'
  ].freeze
end

set :show_exceptions, false
set :raise_errors, false

# Fail fast if in production and secret is not configured
if ENV['RACK_ENV'] == 'production' && JWT_SECRET == 'super_secreto_cambiar_en_produccion'
  raise "JWT secret not configured in production! set WORDGUESS_JWT_SECRET"
end

# ---------------- RACK ATTACK (CORREGIDO) ----------------
class Rack::Attack
  throttle('logins/ip', limit: 5, period: 60) do |req|
    req.ip if req.path == '/api/v1/login' && req.post?
  end

  throttle('attempts/ip', limit: 20, period: 60) do |req|
    req.ip if req.path =~ %r{^/api/v1/games/\d+/attempts$} && req.post?
  end

  self.throttled_response = lambda do |env|
    [429, {'Content-Type' => 'application/json'}, [{ success: false, error: 'rate limit exceeded' }.to_json]]
  end
end

# --- CORRECCIÓN CLAVE: Usar MemoryStore ---
Rack::Attack.cache.store = Rack::Attack::MemoryStore.new

use Rack::Attack if ENV['RACK_ENV'] == 'production'

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

# ---------------- NUEVO: HEALTH CHECK PARA RENDER (SIN /API/V1) ----------------
get '/health' do
  content_type :json
  begin
    DB.test_connection
    { success: true, data: { status: 'ok', db: 'connected' } }.to_json
  rescue
    status 500
    { success: false, error: 'db disconnected' }.to_json
  end
end

# ---------------- SCHEMA (INTACTO) ----------------
DB.create_table? :users do
  primary_key :id
  String :username, unique: true, null: false
  String :password_digest, null: false
  String :role, default: 'user'
  Integer :wins, default: 0
  Integer :losses, default: 0
  DateTime :created_at
end

# Migración para columna role (para bases de datos existentes)
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

# ---------------- HELPERS (INTACTO) ----------------
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
      '/api/v1/register', '/api/v1/login', '/api/v1/health',
      '/api/v1/_seed_demo', '/api/v1/logout', '/openapi.json', '/docs'
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
# (Tus endpoints originales, todos con /api/v1/... se mantienen IGUALES)
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
  jti = token_obj[:jti]

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

# ... (todos tus demás endpoints: refresh, logout, words, games, etc. permanecen exactamente igual) ...
# Por brevedad no los copio enteros aquí, pero en tu archivo final deben estar todos.
