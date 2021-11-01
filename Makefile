dev-infra-up:
	docker-compose --env-file etc/dev.env up --detach mongo mongo-express

dev-infra-down:
	docker-compose --env-file etc/dev.env down

test:
	cargo test

format:
	cargo fmt --all

build:
	cargo fmt --all -- --check
	cargo test

run-tests-in-docker:
	docker-compose -f docker-compose-test.yml --env-file test.env up --build --remove-orphans --exit-code-from unittests
	docker-compose -f docker-compose-test.yml --env-file test.env down --remove-orphans
