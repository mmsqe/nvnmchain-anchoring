.PHONY: check lint test fixtures

# The contracts' event ABI is vendored under tests/fixtures so `cargo test` stays offline.
# Private repo, hence SSH. CONTRACTS_REPO also takes a local path, for regenerating from a
# working copy before the branch is pushed — but that path lands in the fixture's `source`, so
# regenerate from the remote before committing. CONTRACTS_REF takes a branch, tag, or SHA.
CONTRACTS_REPO ?= git@github.com:NVNM-Chain/nvnmchain-contracts.git
CONTRACTS_REF ?= main
CONTRACTS_WORK := .cache/nvnmchain-contracts
FIXTURE := tests/fixtures/contract-events.json

check: lint test

lint:
	cargo fmt --check
	cargo clippy --all-targets -- -D warnings

test:
	cargo test

# Rebuild the vendored event ABI. Needs forge and jq. Rerun on any event change —
# tests/signatures.rs is only as current as what lands here.
fixtures:
	rm -rf $(CONTRACTS_WORK)
	# init+fetch, not clone --branch, so CONTRACTS_REF can be a branch, tag, or SHA.
	git init -q $(CONTRACTS_WORK)
	cd $(CONTRACTS_WORK) && git remote add origin $(CONTRACTS_REPO) && \
	  git fetch -q --depth 1 origin $(CONTRACTS_REF) && git checkout -q FETCH_HEAD && \
	  git submodule update -q --init --depth 1
	cd $(CONTRACTS_WORK) && forge build
	jq -s \
	  --arg repo "$(CONTRACTS_REPO)" \
	  --arg commit "$$(git -C $(CONTRACTS_WORK) rev-parse HEAD)" \
	  '{source: $$repo, commit: $$commit, note: "Regenerate with: make fixtures", \
	    events: ([.[] | .abi[] | select(.type == "event")] \
	             | map({name, inputs: [.inputs[] | {type}]}) | sort_by(.name))}' \
	  $(CONTRACTS_WORK)/out/Registry.sol/Registry.json \
	  $(CONTRACTS_WORK)/out/RegistryFactory.sol/RegistryFactory.json \
	  $(CONTRACTS_WORK)/out/IAnchoring.sol/IAnchoring.json \
	  > $(FIXTURE)
	@echo "wrote $(FIXTURE) (nvnmchain-contracts $$(git -C $(CONTRACTS_WORK) rev-parse --short HEAD))"
