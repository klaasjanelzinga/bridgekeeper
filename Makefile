dev-infra-up:
	docker-compose --env-file etc/dev.env up --detach mongo mongo-express

dev-infra-down:
	docker-compose --env-file etc/dev.env down
