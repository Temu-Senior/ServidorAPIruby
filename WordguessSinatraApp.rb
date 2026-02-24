# WordguessSinatraApp.rb
require 'sinatra'
require 'sinatra/cross_origin'
require 'sequel'
require 'json'
require 'bcrypt'
require 'jwt'
require 'time'
require 'date'

# ---------------- CONFIG ----------------
# Bind y puerto (usa PORT si está en el entorno)
set :bind, '0.0.0.0'
set :port, ENV.fetch('PORT', 4567).to_i

DB_FILE = ENV.fetch('WORDGUESS_DB') { '/app/data/wordguess.db' }
DB = Sequel.sqlite(DB_FILE)
JWT_SECRET = ENV.fetch('WORDGUESS_JWT_SECRET', 'super_secreto_cambiar_en_produccion')
JWT_ALG = 'HS256'

set :show_exceptions, false
set :raise_errors, false

# ---------------- CORS ----------------
configure do
  enable :cross_origin
end

before do
  # Establecemos JSON como content type por defecto y cabeceras CORS
  content_type :json

  # Para permitir que el front envíe cookies (HttpOnly JWT) debemos devolver
  # Access-Control-Allow-Credentials: true y no usar '*' en Allow-Origin.
  origin = request.env['HTTP_ORIGIN'] || request.env['ORIGIN'] || '*'
  response.headers['Access-Control-Allow-Origin'] = origin
  response.headers['Access-Control-Allow-Credentials'] = 'true'
  response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Accept'
  # opcional: setea métodos permitidos
  response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
end

options '*' do
  origin = request.env['HTTP_ORIGIN'] || request.env['ORIGIN'] || '*'
  response.headers['Access-Control-Allow-Origin'] = origin
  response.headers['Access-Control-Allow-Credentials'] = 'true'
  response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
  response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Accept'
  200
end

# ---------------- SCHEMA ----------------
DB.create_table? :users do
  primary_key :id
  String :username, unique: true, null: false
  String :password_digest, null: false
  Integer :wins, default: 0
  Integer :losses, default: 0
  DateTime :created_at
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

USERS = DB[:users]
WORDS = DB[:words]
GAMES = DB[:games]
ATTEMPTS = DB[:attempts]

# ---------------- HELPERS ----------------
helpers do
  def json(data)
    content_type :json
    data.to_json
  end

  def parse_json
    request.body.rewind if request.body.respond_to?(:rewind)
    raw = request.body.read
    return {} if raw.nil? || raw.strip.empty?
    JSON.parse(raw)
  rescue JSON::ParserError
    halt 400, json(error: 'invalid json')
  end

  def hash_password(p)
    BCrypt::Password.create(p)
  end

  def valid_password?(digest, plain)
    BCrypt::Password.new(digest) == plain
  end

  def generate_token(user_id)
    payload = { user_id: user_id, exp: (Time.now + 3 * 3600).to_i }
    JWT.encode(payload, JWT_SECRET, JWT_ALG)
  end

  # Read JWT from HttpOnly cookie and return user row or halt
  def current_user!(halt_on_missing: true)
    token = request.cookies['wg_token']
    if token.nil? || token.strip.empty?
      halt 401, json(error: 'missing token') if halt_on_missing
      return nil
    end

    begin
      decoded = JWT.decode(token, JWT_SECRET, true, algorithm: JWT_ALG)[0]
      user = USERS.where(id: decoded['user_id']).first
      halt 401, json(error: 'invalid user') unless user
      user
    rescue JWT::ExpiredSignature
      halt 401, json(error: 'token expired')
    rescue JWT::DecodeError
      halt 401, json(error: 'invalid token')
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

  # Basic match feedback similar to Wordle
  def match_feedback(word, guess)
    word_s = word.chars
    guess_s = guess.chars
    positions = guess_s.each_with_index.map { |ch, i| ch == word_s[i] }
    # count letter matches (simple approach)
    # note: this is not the exact Wordle algorithm for repeated letters but is enough for feedback
    letter_matches = guess_s.uniq.count { |ch| word_s.include?(ch) }
    {
      correct: guess == word,
      positions: positions,
      letter_matches_count: letter_matches
    }
  end
end

# ---------------- ERRORS ----------------
error do
  e = env['sinatra.error']
  status 500
  json(error: 'internal server error', message: e&.message)
end

# ---------------- ENDPOINTS ----------------

# Health
get '/health' do
  json(status: 'ok', message: 'server running')
end

# Register
post '/register' do
  data = parse_json
  username = data['username']&.strip
  password = data['password']&.strip
  halt 400, json(error: 'username and password required') unless username && password && username != '' && password != ''

  if USERS.where(username: username).first
    halt 409, json(error: 'username taken')
  end

  id = USERS.insert(username: username, password_digest: hash_password(password), created_at: Time.now)
  user = USERS.where(id: id).first
  status 201
  json(message: 'user created', id: user[:id], username: user[:username])
end

# Login
post '/login' do
  data = parse_json
  username = data['username']
  password = data['password']
  halt 400, json(error: 'username and password required') unless username && password

  user = USERS.where(username: username).first
  unless user && valid_password?(user[:password_digest], password)
    halt 401, json(error: 'invalid credentials')
  end

  token = generate_token(user[:id])

  # Cookie HttpOnly for JWT (browser will send it automatically)
  response.set_cookie('wg_token', value: token,
    httponly: true,
    secure: ENV['RACK_ENV'] == 'production',
    same_site: :strict,
    max_age: 3 * 3600
  )

  json(message: 'login successful')
end

# Logout
post '/logout' do
  response.delete_cookie('wg_token')
  json(message: 'logged out')
end

# Create a word (auth required)
post '/words' do
  current_user!
  data = parse_json
  text = data['text']&.strip&.downcase
  difficulty = data['difficulty'] || 'medium'
  date = data['date']

  halt 400, json(error: 'text required') unless text && text != ''

  parsed_date = nil
  if date && !date.to_s.empty?
    parsed_date = begin
      Date.parse(date)
    rescue ArgumentError, TypeError
      nil
    end
    halt 400, json(error: 'invalid date format') unless parsed_date
  end

  id = WORDS.insert(text: text, difficulty: difficulty, date: parsed_date, created_at: Time.now)
  word = WORDS.where(id: id).first
  status 201
  json(message: 'word created', id: word[:id], text: word[:text], difficulty: word[:difficulty], date: word[:date])
end

# List words (filter by date/difficulty)
get '/words' do
  q = WORDS
  if params['date']
    parsed_date = begin
      Date.parse(params['date'])
    rescue ArgumentError, TypeError
      nil
    end
    halt 400, json(error: 'invalid date format') unless parsed_date
    q = q.where(date: parsed_date)
  end
  q = q.where(difficulty: params['difficulty']) if params['difficulty']
  words = q.all.map { |w| { id: w[:id], text: w[:text], difficulty: w[:difficulty], date: w[:date] } }
  json(words: words)
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
    halt 400, json(error: 'invalid date format') unless parsed_date
    word_row = WORDS.where(date: parsed_date).first
    halt 404, json(error: 'no word for that date') unless word_row
  else
    word_row = WORDS.order(Sequel.lit('RANDOM()')).first
    halt 404, json(error: 'no words yet') unless word_row
  end

  attempts_allowed = attempts_for_difficulty(word_row[:difficulty])
  gid = GAMES.insert(user_id: user[:id], word_id: word_row[:id], attempts_allowed: attempts_allowed, attempts_used: 0, status: 'playing', created_at: Time.now, updated_at: Time.now)
  game = GAMES.where(id: gid).first
  status 201
  json(message: 'game started', id: game[:id], attempts_allowed: game[:attempts_allowed], status: game[:status], word_length: word_row[:text].length)
end

# Get game state
get '/games/:id' do |id|
  user = current_user!
  game = GAMES.where(id: id, user_id: user[:id]).first
  halt 404, json(error: 'game not found') unless game
  attempts = ATTEMPTS.where(game_id: game[:id]).all.map { |a| { id: a[:id], guess: a[:guess], correct: a[:correct], created_at: a[:created_at] } }
  word = WORDS.where(id: game[:word_id]).first
  json(id: game[:id], attempts_allowed: game[:attempts_allowed], attempts_used: game[:attempts_used], status: game[:status], attempts: attempts, word_length: word[:text].length)
end

# Submit an attempt
post '/games/:id/attempts' do |id|
  user = current_user!
  game = GAMES.where(id: id, user_id: user[:id]).first
  halt 404, json(error: 'game not found') unless game
  halt 400, json(error: 'game already finished') if %w[won lost].include?(game[:status])

  data = parse_json
  guess = data['guess']&.strip&.downcase
  halt 400, json(error: 'guess required') unless guess

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

  json(message: 'attempt recorded', correct: correct, status: new_status, feedback: feedback)
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
  json(games: games)
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
  json(leaderboard: data)
end

# Seed demo (dev only)
post '/_seed_demo' do
  return json(seed: 'already seeded') if WORDS.count > 0
  WORDS.insert(text: 'apple', difficulty: 'easy', date: Date.today - 1, created_at: Time.now)
  WORDS.insert(text: 'zebra', difficulty: 'medium', date: Date.today, created_at: Time.now)
  WORDS.insert(text: 'query', difficulty: 'hard', date: Date.today + 1, created_at: Time.now)
  json(seed: 'ok')
end

# ---------------- OPENAPI (complete) ----------------
get '/openapi.json' do
  spec = {
    openapi: '3.0.1',
    info: {
      title: 'Wordguess API',
      version: '1.0.0',
      description: 'Wordguess API (Sinatra) with JWT stored in HttpOnly cookie'
    },
    servers: [
      { url: request.base_url }
    ],
    components: {
      securitySchemes: {
        cookieAuth: {
          type: 'apiKey',
          in: 'cookie',
          name: 'wg_token'
        },
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT'
        }
      },
      schemas: {
        User: {
          type: 'object',
          properties: {
            id: { type: 'integer' },
            username: { type: 'string' }
          }
        },
        RegisterRequest: {
          type: 'object',
          properties: { username: { type: 'string' }, password: { type: 'string' } },
          required: ['username','password']
        },
        LoginRequest: {
          type: 'object',
          properties: { username: { type: 'string' }, password: { type: 'string' } },
          required: ['username','password']
        },
        Word: {
          type: 'object',
          properties: { id: { type: 'integer' }, text: { type: 'string' }, difficulty: { type: 'string' }, date: { type: 'string', format: 'date' } }
        },
        Game: {
          type: 'object',
          properties: { id: { type: 'integer' }, attempts_allowed: { type: 'integer' }, attempts_used: { type: 'integer' }, status: { type: 'string' }, word_length: { type: 'integer' } }
        },
        Attempt: {
          type: 'object',
          properties: { id: { type: 'integer' }, guess: { type: 'string' }, correct: { type: 'boolean' }, created_at: { type: 'string', format: 'date-time' } }
        }
      }
    },
    paths: {
      '/health' => {
        get: {
          summary: 'Health check',
          responses: { '200' => { description: 'OK', content: { 'application/json' => { example: { status: 'ok', message: 'server running' } } } } }
        }
      },
      '/register' => {
        post: {
          summary: 'Register user',
          requestBody: { required: true, content: { 'application/json' => { schema: { '$ref' => '#/components/schemas/RegisterRequest' } } } },
          responses: {
            '201' => { description: 'Created', content: { 'application/json' => { example: { message: 'user created', id: 1, username: 'angel' } } } },
            '400' => { description: 'Bad Request' },
            '409' => { description: 'Conflict' }
          }
        }
      },
      '/login' => {
        post: {
          summary: 'Login (sets HttpOnly cookie)',
          requestBody: { required: true, content: { 'application/json' => { schema: { '$ref' => '#/components/schemas/LoginRequest' } } } },
          responses: {
            '200' => { description: 'OK', content: { 'application/json' => { example: { message: 'login successful' } } } },
            '400' => { description: 'Bad Request' },
            '401' => { description: 'Unauthorized' }
          }
        }
      },
      '/logout' => {
        post: {
          summary: 'Logout (deletes cookie)',
          responses: { '200' => { description: 'OK', content: { 'application/json' => { example: { message: 'logged out' } } } } }
        }
      },
      '/words' => {
        get: {
          summary: 'List words',
          parameters: [
            { name: 'date', in: 'query', schema: { type: 'string', format: 'date' }, required: false },
            { name: 'difficulty', in: 'query', schema: { type: 'string' }, required: false }
          ],
          responses: { '200' => { description: 'OK' } }
        },
        post: {
          summary: 'Create word (auth required)',
          security: [{ cookieAuth: [] }],
          requestBody: { required: true, content: { 'application/json' => { schema: { type: 'object', properties: { text: { type: 'string' }, difficulty: { type: 'string' }, date: { type: 'string', format: 'date' } }, required: ['text'] } } } },
          responses: { '201' => { description: 'Created' }, '400' => { description: 'Bad Request' }, '401' => { description: 'Unauthorized' } }
        }
      },
      '/games' => {
        post: {
          summary: 'Start game (auth required)',
          security: [{ cookieAuth: [] }],
          requestBody: { required: false, content: { 'application/json' => { schema: { type: 'object', properties: { date: { type: 'string', format: 'date' } } } } } },
          responses: { '201' => { description: 'Game started' }, '400' => { description: 'Bad Request' }, '401' => { description: 'Unauthorized' }, '404' => { description: 'Not Found' } }
        }
      },
      '/games/{id}' => {
        get: {
          summary: 'Get game state (auth required)',
          security: [{ cookieAuth: [] }],
          parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }],
          responses: { '200' => { description: 'OK' }, '401' => { description: 'Unauthorized' }, '404' => { description: 'Not Found' } }
        }
      },
      '/games/{id}/attempts' => {
        post: {
          summary: 'Submit attempt',
          security: [{ cookieAuth: [] }],
          parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }],
          requestBody: { required: true, content: { 'application/json' => { schema: { type: 'object', properties: { guess: { type: 'string' } }, required: ['guess'] } } } },
          responses: { '200' => { description: 'Attempt recorded' }, '400' => { description: 'Bad Request' }, '401' => { description: 'Unauthorized' }, '404' => { description: 'Not Found' } }
        }
      },
      '/me/games' => {
        get: {
          summary: "Get user's games (auth required)",
          security: [{ cookieAuth: [] }],
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

  json(spec)
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

# Servir frontend estático
get '/' do
  send_file File.join(settings.root, 'frontend', 'index.html')
end

# Servir otros assets de la carpeta frontend (CSS, JS, imágenes)
set :public_folder, File.join(settings.root, 'frontend')

# Run server (si se ejecuta el archivo directamente)
if __FILE__ == $0
  port = settings.port || ENV.fetch('PORT', 4567).to_i
  puts "Starting Wordguess Sinatra API on port #{port} -- DB: #{DB_FILE}"
  Sinatra::Application.run! port: port, bind: '0.0.0.0'
end