build:
	cargo build --target wasm32-wasip1 --release
run:
	cargo build --target wasm32-wasip1 --release
	docker-compose up
run-background:
	cargo build --target wasm32-wasip1 --release
	docker-compose up -d
docker-image:
	docker buildx build --platform linux/amd64 -f Dockerfile -t antonengelhardt/wasm-oidc-plugin:latest .
docker-push:
	docker push antonengelhardt/wasm-oidc-plugin:latest
clean:
	docker-compose rm --force
