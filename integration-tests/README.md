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

!!! warning
    Adjust the `.env` and `envoy.yaml` files to your needs.

```bash
docker-compose up -d
pytest test.py
```
