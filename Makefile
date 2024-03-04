# Command to build new wasm file, docker-compose up and curl to test
simulate:
	cargo build --target wasm32-wasi --release
	docker-compose up
clean:
	docker-compose rm --force
integration-test:
	cargo build --target wasm32-wasi --release
	docker-compose -f integration-tests/docker-compose.yaml up -d
	pytest integration-tests/test.py
	docker-compose -f integration-tests/docker-compose.yaml down
