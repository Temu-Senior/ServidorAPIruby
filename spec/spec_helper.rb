require 'rack/test'
require 'rspec'

ENV['RACK_ENV'] = 'test'
require_relative '../WordguessSinatraApp'

module RSpecMixin
  include Rack::Test::Methods
  def app() Sinatra::Application end
end

RSpec.configure do |c|
  c.include RSpecMixin
end