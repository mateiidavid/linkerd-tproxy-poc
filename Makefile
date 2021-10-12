TPROXY_IMAGE ?= latest
ECHO_IMAGE ?= latest
CLUSTER_NAME ?= dev

#-----------------#
# TPROXY & SERVER #
#-----------------#
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

.PHONY: kind-load
kind-load:
	kind load docker-image tproxy-poc:$(TPROXY_IMAGE) --name kind
	kind load docker-image echo-server:$(TPROXY_IMAGE) --name kind

#-----------------#
# TPROXY          #
#-----------------#
.PHONY: tproxy
tproxy: tproxy-poc tproxy-image

.PHONY: tproxy-image
tproxy-image: ## Loads tproxy into k3d
	k3d image import --cluster $(CLUSTER_NAME) tproxy-poc:$(TPROXY_IMAGE)


