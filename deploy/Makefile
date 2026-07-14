.PHONY: build test test-integration image up down logs

REPO_ROOT := ..
SUB2API_BUILD_VERSION ?= development

build:
	@$(MAKE) -C $(REPO_ROOT) build

test:
	@$(MAKE) -C $(REPO_ROOT) test

test-integration:
	@$(MAKE) -C $(REPO_ROOT) test-rust-integration

image:
	@docker build \
		--build-arg SUB2API_BUILD_VERSION=$(SUB2API_BUILD_VERSION) \
		-t sub2api:latest \
		-f $(REPO_ROOT)/Dockerfile \
		$(REPO_ROOT)

up:
	@docker compose up -d --build --remove-orphans

down:
	@docker compose down

logs:
	@docker compose logs -f sub2api
