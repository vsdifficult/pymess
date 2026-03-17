# Free-tier deployment (Supabase + FastAPI)

## 1) Supabase (free tier)
- Create a project and copy `SUPABASE_URL` + `SUPABASE_SERVICE_ROLE_KEY`.
- Apply SQL migrations from `backend_supabase/migrations`.
- Enable Realtime for encrypted tables only.
- Enforce retention jobs to stay under 500k rows.
- Keep Storage under 1 GB by client-side attachment TTL policies.

## 2) Backend runtime
Set env vars:
- Core: `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, `PYMESS_JWT_SECRET`
- Security: `PYMESS_REPLAY_TTL_SECONDS`, `PYMESS_MAX_CIPHERTEXT_B64_LEN`
- Free-tier: `PYMESS_MAX_DB_ROWS_SOFT_LIMIT=450000`
- Integrations: `PUSH_FIREBASE_TOKEN`, `PUSH_ONESIGNAL_TOKEN`, `OAUTH_GOOGLE_KEY`, `OAUTH_APPLE_KEY`, `ANALYTICS_TOKEN`

## 3) CI/CD (free)
- Use GitHub Actions workflow `.github/workflows/ci.yml`.
- Build and test on PR.
- Deploy API to low-cost/free runners (Railway/Render/Fly free offers subject to change).

## 4) Hardening checklist
- Rotate service-role key and JWT secret periodically.
- Enable MFA in Supabase dashboard for admin accounts.
- Add RLS policies if exposing PostgREST directly to clients.
