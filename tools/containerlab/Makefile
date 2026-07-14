LAB_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
REPO_ROOT := $(abspath $(LAB_DIR)/../..)

DOCKER ?= docker
CONTAINERLAB ?= containerlab

IMAGE := gobgp:local
TOPOLOGY := gobgp.clab.yml

.PHONY: build deploy inspect verify destroy

build:
	$(DOCKER) build \
		--file "$(LAB_DIR)/Dockerfile" \
		--tag "$(IMAGE)" \
		"$(REPO_ROOT)"

deploy: build
	cd "$(LAB_DIR)" && $(CONTAINERLAB) deploy --topo "$(TOPOLOGY)"

inspect:
	cd "$(LAB_DIR)" && $(CONTAINERLAB) inspect --topo "$(TOPOLOGY)"

verify:
	cd "$(LAB_DIR)" && $(CONTAINERLAB) exec --topo "$(TOPOLOGY)" --cmd 'ip -brief address show dev eth1'
	cd "$(LAB_DIR)" && $(CONTAINERLAB) exec --topo "$(TOPOLOGY)" --cmd 'gobgp neighbor'
	cd "$(LAB_DIR)" && $(CONTAINERLAB) exec --topo "$(TOPOLOGY)" --cmd 'gobgp global rib'

destroy:
	cd "$(LAB_DIR)" && $(CONTAINERLAB) destroy --topo "$(TOPOLOGY)" --cleanup
