dev-infra-up:
	docker-compose --env-file etc/dev.env up --detach mongo mongo-express

dev-infra-down:
	docker-compose --env-file etc/dev.env down

test:
	cargo test

format:
	cargo fmt --all

check:
	cargo fmt --all -- --check
	cargo check

build-release:
	cargo build --release

install-musl-build: build-release
	cargo install --target x86_64-unknown-linux-musl --path .

run-tests-in-docker:
	docker-compose -f docker-compose-test.yml --env-file etc/test.env up --build --remove-orphans --exit-code-from unittests
	docker-compose -f docker-compose-test.yml --env-file etc/test.env down --remove-orphans

run-build-in-docker:
	docker build -t bridgekeeper-build --file docker-files/build/Dockerfile .
	docker run -v `pwd`:/usr/src/app -it bridgekeeper-build ./entrypoint-build.sh

scp-to-host:
	scp Makefile docker-compose-live.yml scp://test.n-kj.nl//usr/bridgekeeper
	scp -r etc/production.env scp://test.n-kj.nl//usr/bridgekeeper/etc

