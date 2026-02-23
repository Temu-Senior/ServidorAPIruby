FROM ruby:3.2-slim

WORKDIR /app
COPY Gemfile* /app/
RUN bundle install --jobs 4 --retry 3

COPY . /app
EXPOSE 4567

ENV RACK_ENV=production
CMD ["ruby", "WordguessSinatraApp.rb"]