-- Free-tier retention helpers
create or replace function prune_expired_messages() returns void
language sql
as $$
  delete from encrypted_messages
  where expires_at is not null and expires_at < now();
$$;

create or replace function prune_old_messages(max_rows integer default 450000) returns void
language plpgsql
as $$
declare
  cnt integer;
  trim_count integer;
begin
  select count(*) into cnt from encrypted_messages;
  if cnt > max_rows then
    trim_count := least(cnt - max_rows, 2000);
    delete from encrypted_messages
    where id in (
      select id from encrypted_messages order by id asc limit trim_count
    );
  end if;
end;
$$;
