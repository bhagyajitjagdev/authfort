<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/bhagyajitjagdev/authfort/main/.github/logo-dark.svg" width="60">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/bhagyajitjagdev/authfort/main/.github/logo-light.svg" width="60">
  <img alt="AuthFort" src="https://raw.githubusercontent.com/bhagyajitjagdev/authfort/main/.github/logo-light.svg" width="60">
</picture>

# authfort-service

[![PyPI](https://img.shields.io/pypi/v/authfort-service)](https://pypi.org/project/authfort-service/)
[![Coverage](https://codecov.io/gh/bhagyajitjagdev/authfort/branch/main/graph/badge.svg?flag=service)](https://codecov.io/gh/bhagyajitjagdev/authfort)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docs](https://img.shields.io/badge/Docs-blue?logo=readthedocs&logoColor=white)](https://bhagyajitjagdev.github.io/authfort/service/)

</div>

Lightweight JWT verification for microservices powered by AuthFort.

## Install

```bash
pip install authfort-service[fastapi]
```

## Quick Start

```python
from authfort_service import ServiceAuth
from fastapi import FastAPI, Depends

service = ServiceAuth(
    jwks_url="https://auth.example.com/.well-known/jwks.json",
    issuer="authfort",
)

app = FastAPI()

@app.get("/api/data")
async def protected(user=Depends(service.current_user)):
    return {"user_id": user.sub, "roles": user.roles}

@app.get("/api/admin")
async def admin_only(user=Depends(service.require_role("admin"))):
    return {"message": "admin access"}
```

## Features

- JWKS fetching with automatic caching and refresh
- JWT signature verification (RS256)
- Token introspection client (optional real-time validation)
- FastAPI integration (current_user, require_role dependencies)
- No database required

## With Introspection

```python
service = ServiceAuth(
    jwks_url="https://auth.example.com/.well-known/jwks.json",
    issuer="authfort",
    introspect_url="https://auth.example.com/auth/introspect",
    introspect_secret="shared-secret",
)

# Real-time validation (checks ban status, token version, fresh roles)
result = await service.introspect(token)
```

## License

[MIT](../LICENSE)
