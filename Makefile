.PHONY: orbstack-dev orbstack-dev-clean

orbstack-dev:
	@./.hack/orbstack.sh

orbstack-dev-clean:
	@./.hack/orbstack.sh cleanup
