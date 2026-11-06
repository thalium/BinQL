COMPILER_IMAGE := binql-tests-compiler

MAKEFLAGS += --no-print-directory

SUBDIRS := $(dir $(shell find ida -name Makefile))

.PHONY: all clean clean-docker clean-subdirs binary list-compile compile docker-build docker-run

# Human commands

all: docker-build docker-run

clean: clean-subdirs

clean-docker:
	-@docker ps -aq --filter ancestor=$(COMPILER_IMAGE) | xargs -r docker rm -f
	-@docker rmi -f $(COMPILER_IMAGE)
	docker image prune -f

clean-subdirs:
	@for d in $(SUBDIRS); do \
		echo "Cleaning $$d"; \
		$(MAKE) -C $$d clean || exit 1; \
	done

binary: docker-build docker-run

# Container commands

list-compile:
	@for d in $(SUBDIRS); do \
		echo "===> $$d"; \
	done

compile:
	@for d in $(SUBDIRS); do \
		echo "===> $$d"; \
		$(MAKE) -C $$d || exit 1; \
	done

# Host related to docker image, container

docker-build:
	docker build --quiet --tag binql-tests-compiler .

docker-run:
	docker run --rm \
		-v "$(CURDIR):/work" \
		--user $$(id -u):$$(id -g) \
		$(COMPILER_IMAGE)
