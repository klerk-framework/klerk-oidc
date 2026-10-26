# Klerk OIDC

Login with OpenID Connect for Klerk applications that use [klerk-web-extra](../klerk-web-extra/README.md): Microsoft Entra ID,
Keycloak, Google and other providers. The user ends up in the same session as with a login by email link.

* [Login with OpenID Connect](docs/oidc.md)

## Installation

```kotlin
implementation(platform("dev.klerkframework:klerk-bom:$klerkBomVersion"))
implementation("dev.klerkframework:klerk")
implementation("dev.klerkframework:klerk-web")
implementation("dev.klerkframework:klerk-web-extra")
implementation("dev.klerkframework:klerk-oidc")
```
