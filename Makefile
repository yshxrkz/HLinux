# Common tasks. The tests need root (and Docker for test-docker); none of
# them change the machine they run on - hardening only ever happens inside
# the demo container.

SHELL_FILES := harden-audit.sh $(wildcard lib/*.sh lib/controls/*.sh tests/*.sh docker/*.sh)
IMAGE       ?= harden-audit-demo

.PHONY: help lint test test-docker demo audit clean

help:
	@echo "make lint         shellcheck, hadolint and actionlint"
	@echo "make test         host tests (read-only; needs root: sudo make test)"
	@echo "make test-docker  build the demo container and run the end-to-end tests in it"
	@echo "make demo         audit -> harden -> audit inside the demo container"
	@echo "make audit        audit this machine (read-only) and write reports/audit.html"

lint:
	shellcheck $(SHELL_FILES)
	@if command -v hadolint >/dev/null; then hadolint Dockerfile; else echo "hadolint not installed - skipped"; fi
	@if command -v actionlint >/dev/null; then actionlint; else echo "actionlint not installed - skipped"; fi

test:
	tests/run-tests.sh

test-docker:
	tests/docker-test.sh reports

demo:
	docker build --tag $(IMAGE) .
	mkdir -p reports && chmod 777 reports
	docker run --rm -it --cap-add NET_ADMIN --volume "$(CURDIR)/reports:/reports" $(IMAGE)

audit:
	mkdir -p reports
	./harden-audit.sh audit --report reports/audit.html

clean:
	rm -rf reports
