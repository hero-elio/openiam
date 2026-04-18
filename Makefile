.PHONY: build-frontend embed-frontend build

build-frontend:
	cd web/authn-test && npm install && npm run build

embed-frontend: build-frontend
	rm -rf pkg/authn_test_dist
	cp -r web/authn-test/dist pkg/authn_test_dist

build: embed-frontend
	go build ./...
