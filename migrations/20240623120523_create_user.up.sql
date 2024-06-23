-- Add migration script here
create table user (
    user_id uuid primary key,
    username text unique not null,
    email text unique not null,
    password_hash text not null,
    created_at time
)
