# Supabase backend assets

1. Apply `migrations/001_init.sql` then `migrations/002_retention.sql`.
2. Enable Realtime for `encrypted_messages` and `group_messages`.
3. Create bucket `encrypted-files` for client-side encrypted attachments.
4. Configure Supabase Auth providers (email/password + optional OAuth).
5. (Optional) Schedule `select prune_expired_messages();` and `select prune_old_messages(450000);` with pg_cron.
