require 'spec_helper'

RSpec.describe 'Wordguess API' do
  it 'health check' do
    get '/health'
    expect(last_response.status).to eq(200)
    expect(JSON.parse(last_response.body)['status']).to eq('ok')
  end

  it 'register and login' do
    post '/register', { username: 'spec_user', password: 'abc123' }.to_json, { 'CONTENT_TYPE' => 'application/json' }
    expect(last_response.status).to eq(200)
    post '/login', { username: 'spec_user', password: 'abc123' }.to_json, { 'CONTENT_TYPE' => 'application/json' }
    expect(last_response.status).to eq(200)
    body = JSON.parse(last_response.body)
    expect(body['token']).not_to be_nil
  end
end