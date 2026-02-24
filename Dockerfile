FROM ruby:3.2-slim

WORKDIR /app
COPY Gemfile* /app/

# Esto se ejecutará dentro del contenedor
RUN apt-get update && \
    apt-get install -y build-essential libsqlite3-dev && \
    rm -rf /var/lib/apt/lists/*

RUN bundle install --jobs 4 --retry 3

COPY . /app

EXPOSE 4567
ENV RACK_ENV=production
CMD ["ruby", "WordguessSinatraApp.rb"]