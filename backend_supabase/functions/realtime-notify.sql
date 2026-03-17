create or replace function notify_new_encrypted_message()
returns trigger
language plpgsql
as $$
begin
  perform pg_notify('pymess_encrypted_messages', row_to_json(new)::text);
  return new;
end;
$$;

create trigger trg_notify_new_encrypted_message
after insert on encrypted_messages
for each row execute function notify_new_encrypted_message();
