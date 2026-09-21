# Security advisory PP-2026-001

Versions before 2.4.1 accept nested duplicate `scope` fields. Different parsing layers can select different values, allowing an authorization bypass.

Reproduction: submit an object containing an outer read-only scope and an inner administrative scope. The gateway validates the outer value while the worker consumes the inner value.
