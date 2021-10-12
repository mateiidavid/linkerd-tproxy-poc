TPROXY_IMAGE ?= latest
ECHO_IMAGE ?= latest
CLUSTER_NAME ?= dev

.PHONY: all
all: tproxy-poc server load-image

.PHONY: tproxy-poc
tproxy-poc: ## Build tproxy image
	DOCKER_BUILDKIT=1 docker build -t tproxy-poc:$(TPROXY_IMAGE) -f Dockerfile-tproxy .

.PHONY: server
server: ## Build echo server image
	DOCKER_BUILDKIT=1 docker build -t echo-server:$(ECHO_IMAGE) -f Dockerfile-server .

.PHONY: load-image
load-image: ## Loads image into k3d
	k3d image import --cluster $(CLUSTER_NAME) tproxy-poc:$(TPROXY_IMAGE) echo-server:$(ECHO_IMAGE)



