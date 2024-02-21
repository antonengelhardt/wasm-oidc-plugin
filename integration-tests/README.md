# Integration Tests

This directory contains integration tests for the `wasm-oidc-plugin`-project.

## Prerequisites

- [Docker](https://www.docker.com/)
- [Docker Compose](https://docs.docker.com/compose/)
- [Python 3](https://www.python.org/)
- [pip](https://pypi.org/project/pip/)

Install the required Python packages:

```bash
pip install -r requirements.txt
```

## Running the tests

> [!IMPORTANT]
> Adjust the `.env` and `envoy.yaml` files to your needs. You need to replace the `config_endpoint`, `client_id`, `client_secret`, `redirect_uri`, `issuer`, `audience` and `aes_key` with your own values. In the CI, [Auth0](https://auth0.com) is used as the identity provider. The `aes_key` can be generated with `openssl rand -base64 32`.

Then run build the plugin and run the tests:

```bash
# Build the plugin
cargo build --release --target=wasm32-wasi

# Run the tests
cd integration-tests
docker-compose up -d
pytest test.py
```
