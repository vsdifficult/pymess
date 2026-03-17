# Security testing checklist

- [ ] E2EE envelope never includes plaintext.
- [ ] Private keys remain client-side only.
- [ ] Replay attack blocked (nonce + timestamp TTL).
- [ ] Device binding validated on every protected route.
- [ ] JWT expiration and refresh rotation tested.
- [ ] Ciphertext size limits enforced.
- [ ] TLS endpoint and certificate pinning configured in clients.
- [ ] Supabase tables contain ciphertext-only payload columns.
