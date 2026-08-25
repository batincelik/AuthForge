.PHONY: dev up down build migrate migration test test-security lint format demo clean validate
dev: up
up:
	docker compose up --build
down:
	docker compose down
build:
	docker compose build
migrate:
	PYTHONPATH=apps/api alembic upgrade head
migration:
	@test -n "$(name)" || (echo "usage: make migration name=description" && exit 1)
	PYTHONPATH=apps/api alembic revision --autogenerate -m "$(name)"
test:
	PYTHONPATH=apps/api pytest
test-security:
	PYTHONPATH=apps/api pytest apps/api/tests/security
lint:
	ruff check apps packages scripts
	mypy apps/api/authforge
	npm run typecheck
format:
	ruff format apps packages
validate:
	docker compose config --quiet
demo:
	python scripts/demo.py
clean:
	docker compose down
