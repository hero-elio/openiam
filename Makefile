.PHONY: build-frontend embed-frontend admin build bootstrap

build-frontend:
	cd web/authn-test && npm install && npm run build

embed-frontend: build-frontend
	rm -rf pkg/authn_test_dist
	cp -r web/authn-test/dist pkg/authn_test_dist

admin:
	cd web/admin && pnpm install && pnpm build:embed

build: embed-frontend admin
	go build ./...

# Provision the very first super_admin user. Override defaults via env vars, e.g.:
#   make bootstrap TENANT=acme APP=portal EMAIL=admin@example.com PASSWORD='S3cret!!'
TENANT ?= default
APP ?= admin
EMAIL ?=
PASSWORD ?=
bootstrap:
	@if [ -z "$(EMAIL)" ] || [ -z "$(PASSWORD)" ]; then \
		echo "EMAIL and PASSWORD are required. Example:"; \
		echo "  make bootstrap EMAIL=admin@example.com PASSWORD='S3cret!!'"; \
		exit 2; \
	fi
	./scripts/bootstrap.sh --tenant=$(TENANT) --app=$(APP) --email=$(EMAIL) --password='$(PASSWORD)'
