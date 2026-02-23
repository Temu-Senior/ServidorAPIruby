# db/migrations/001_create_tables.rb
Sequel.migration do
  change do
    create_table?(:users) do
      primary_key :id
      String :username, null: false, unique: true
      String :password_digest, null: false
      Integer :wins, default: 0
      Integer :losses, default: 0
      DateTime :created_at
    end

    create_table?(:words) do
      primary_key :id
      String :text, null: false
      String :difficulty, null: false
      Date :date
      DateTime :created_at
    end

    create_table?(:games) do
      primary_key :id
      foreign_key :user_id, :users
      foreign_key :word_id, :words
      Integer :attempts_allowed
      Integer :attempts_used, default: 0
      String :status, default: 'playing'
      DateTime :created_at
      DateTime :updated_at
    end

    create_table?(:attempts) do
      primary_key :id
      foreign_key :game_id, :games
      String :guess
      Boolean :correct
      DateTime :created_at
    end
  end
end