# Patch report for PP-2026-001

Version 2.4.1 canonicalizes the request exactly once and rejects duplicate security-sensitive fields before authorization. Regression coverage includes nested, reordered, malformed, and mixed-encoding payloads. Alternate parser integrations must enable canonical mode; this residual configuration risk is documented.
