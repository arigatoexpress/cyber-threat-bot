## Summary

-

## Blast Radius

-

## Test Plan

- [ ] `ruff check src tests`
- [ ] `PYTHONPATH=src pytest tests/ -q`

## Rollback

-

## Safety

- [ ] No secrets, private data, exploit payloads, or live credentialed feed calls are included.
- [ ] New or changed outputs are escaped or treated as untrusted text by downstream consumers.
