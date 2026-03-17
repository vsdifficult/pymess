create extension if not exists pgcrypto;

create table if not exists users (
  id bigint generated always as identity primary key,
  username text unique not null,
  password_hash text not null,
  device_id text not null,
  identity_key text not null,
  signed_prekey text not null,
  created_at timestamptz not null default now()
);

create table if not exists contacts (
  user_id bigint not null references users(id) on delete cascade,
  contact_id bigint not null references users(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (user_id, contact_id)
);

create table if not exists refresh_tokens (
  id bigint generated always as identity primary key,
  user_id bigint not null references users(id) on delete cascade,
  token text unique not null,
  expires_at timestamptz not null,
  revoked boolean not null default false,
  created_at timestamptz not null default now()
);

create table if not exists encrypted_messages (
  id bigint generated always as identity primary key,
  msg_id text unique not null,
  sender_id bigint not null references users(id) on delete cascade,
  recipient_id bigint not null references users(id) on delete cascade,
  nonce text not null,
  ciphertext text not null,
  aad text,
  ratchet_header text not null,
  timestamp timestamptz not null,
  expires_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists groups (
  group_id text primary key default encode(gen_random_bytes(12), 'hex'),
  owner_id bigint not null references users(id) on delete cascade,
  group_name text not null,
  encrypted_group_key text not null,
  created_at timestamptz not null default now()
);

create table if not exists group_members (
  group_id text not null references groups(group_id) on delete cascade,
  user_id bigint not null references users(id) on delete cascade,
  joined_at timestamptz not null default now(),
  primary key (group_id, user_id)
);

create table if not exists group_messages (
  id bigint generated always as identity primary key,
  group_id text not null references groups(group_id) on delete cascade,
  sender_id bigint not null references users(id) on delete cascade,
  msg_id text unique not null,
  nonce text not null,
  ciphertext text not null,
  aad text,
  timestamp timestamptz not null,
  created_at timestamptz not null default now()
);

create index if not exists idx_messages_recipient on encrypted_messages(recipient_id);
create index if not exists idx_contacts_user on contacts(user_id);
create index if not exists idx_group_messages_group on group_messages(group_id);
