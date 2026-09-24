# SunsetQuorum Consumer Migration Evidence

- Service ID: `sunset-demo-api`
- Revision: `1`
- Consumer ID: `consumer-alpha`
- Consumer account: `0xeb57bc7125fa60d7482ce12058397369ab3581f8`
- Consumer repository: `eaglebooth/patchproof`
- Sealed terms digest: `b65a0b4d362f104dac887e33f143a0550fbfc079f7773f7a753f6c79a02ea0e2`

## Endpoint and response migration

The PatchProof consumer replaced `GET /v1/customer-profile/{id}` with `GET /v2/customers/{id}/profile`. Its adapter maps legacy `customer.id` to `id` and `customer.display_name` to `displayName`.

## Authentication

The legacy `X-Legacy-Key` header was removed. The client now obtains an OAuth 2 bearer token and requires the `profile:read` scope before calling the replacement endpoint.

## Error semantics and regression results

The consumer now treats HTTP 404 with an RFC 9457 problem document as the missing-record result. Regression cases for success, missing record, unauthorized token, and upstream failure passed against the replacement adapter.

## Rollback

Rollback was tested by switching the client feature flag back to the legacy adapter, restoring `X-Legacy-Key`, and replaying the same four regression cases. No on-chain revision fields are altered by rollback.
