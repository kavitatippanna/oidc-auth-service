# OpenID Connect Authentication & User Profile Service

This project supports OpenID Connect (OIDC) authentication across multiple
OIDC providers.

## Tech stack

This project is developed using Quarkus framework and uses Caffeine for in-memory
caching and Nimbus OAuth2 SDK for the wire protocol.

## Features
- OIDC Provider and Client configuration using YAML.
- Authentication support using any of the configured OpenID Connect providers.
- Issuance of JWT user token to clients after authentication for the clients to access protected resources hosted in Authentication service.
- Cache user-profile information for a configured period to prevent frequent round-trips to OIDC UserInfo endpoint.
- Logout support which revokes the issued user token so that it cannot be used to access protected resources after logout.

## Roadmap
- Proof-Key Code Exchange (PKCE) support for additional security.
- Fault-tolerance to re-try failed requests.
- Rate limit requests to Authentication service.
- Persistence support to durably store OIDC provider access tokens and user profile information.
- Reactive Extensions support to scale the service to handle concurrent requests using minimum number of threads.
- Health check and metrics for observability.

