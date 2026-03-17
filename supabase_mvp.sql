-- Minimal Supabase schema for encrypted MVP messenger
create table if not exists users (
  id uuid primary key,
  username text unique not null,
  public_key text not null
);

create table if not exists messages (
  id bigint generated always as identity primary key,
  sender_id uuid not null,
  receiver_id uuid not null,
  ciphertext text not null,
  created_at timestamptz not null default now()
);

-- Minimal RLS baseline (adjust policies for production)
alter table users enable row level security;
alter table messages enable row level security;

create policy if not exists users_select_all on users for select using (true);
create policy if not exists users_insert_self on users for insert with check (auth.uid() = id);
create policy if not exists users_update_self on users for update using (auth.uid() = id);

create policy if not exists messages_select_mine on messages
for select using (auth.uid() = sender_id or auth.uid() = receiver_id);

create policy if not exists messages_insert_sender on messages
for insert with check (auth.uid() = sender_id);
