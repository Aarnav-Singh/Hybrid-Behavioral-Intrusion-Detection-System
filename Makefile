.PHONY: install setup dev build up down test lint clean

install: setup

setup:
	chmod +x scripts/*.sh
	./scripts/dev_setup.sh

dev:
	./scripts/dev_run.sh

build:
	docker compose build

up:
	docker compose up -d

down:
	docker compose down

test:
	cd backend && poetry run pytest -v

lint:
	cd backend && poetry run flake8 . && poetry run black .
	cd frontend && npm run lint

clean:
	rm -rf backend/.pytest_cache
	rm -rf backend/__pycache__
	rm -rf frontend/dist
	docker compose down -v
