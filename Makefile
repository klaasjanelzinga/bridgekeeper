dev-infra-up:
	docker-compose --env-file etc/dev.env up --detach mongo mongo-express

dev-infra-down:
	docker-compose --env-file etc/dev.env down

test:
	RUST_BACKTRACE=1 cargo test

format:
	cargo fmt --all
	cargo check
	cargo check --tests

check:
	cargo fmt --all -- --check
	cargo check
	cargo check --tests

build-release:
	cargo build --release

install-musl-build:
	cargo install --target x86_64-unknown-linux-musl --path .
	strip target/x86_64-unknown-linux-musl/release/bridgekeeper

run-tests-in-docker:
	docker-compose -f docker-compose-test.yml --env-file etc/test.env up --build --remove-orphans --exit-code-from unittests
	docker-compose -f docker-compose-test.yml --env-file etc/test.env down --remove-orphans

run-tests-in-docker-cicd:
	# test.env will be decrypted in an earlier step.
	docker-compose -f docker-compose-test.yml --env-file test.env up --build --remove-orphans --exit-code-from unittests
	docker-compose -f docker-compose-test.yml --env-file test.env down --remove-orphans

run-build-in-docker:
	docker build -t bridgekeeper-build --file docker-files/build/Dockerfile .
	docker run -v `pwd`:/usr/src/app bridgekeeper-build ./docker-files/build/entrypoint-build.sh

scp-to-host:
	scp Makefile docker-compose-live.yml scp://test.n-kj.nl//usr/bridgekeeper
	scp -r etc/production.env scp://test.n-kj.nl//usr/bridgekeeper/etc

live-up:
	docker-compose -f docker-compose-live.yml --env-file etc/production.env pull
	docker-compose -f docker-compose-live.yml --env-file etc/production.env down
	docker-compose -f docker-compose-live.yml --env-file etc/production.env up --detach

live-down:
	docker-compose -f docker-compose-live.yml --env-file etc/production.env down
