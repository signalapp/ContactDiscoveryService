##
## Copyright (C) 2020 Signal Messenger, LLC.
## All rights reserved.
##
## SPDX-License-Identifier: AGPL-3.0-or-later
##

V ?= 0
ifeq ($V,0)
	Q = @
else
	Q = 
	CARGO_VERBOSE = -vv
endif

CARGO ?= cargo $(CARGO_VERBOSE)

##
## targets
##

.PHONY: default all all-debug cds-api-client cds-api-client-debug doc check test clippy distclean clean
.PHONY: FORCE

default: all

all: cds-api-client

all-debug: cds-api-client-debug

cds-api-client:
	$(Q) $(CARGO) build --package=cds_api_client --bins --release

cds-api-client-debug:
	$(Q) $(CARGO) build --package=cds_api_client --bins

doc:
	$(Q) $(CARGO) doc --package=cds_api_client --no-deps --release --document-private-items --lib

check:
	$(Q) rm -rf $(targetdir)/debug/incremental
	$(Q) $(CARGO) check --package=cds_api_client --lib --bins --tests

test:
	$(Q) RUST_BACKTRACE=1 $(CARGO) test --workspace

clippy:
	$(Q) rm -rf $(targetdir)/debug/incremental
	$(Q) $(CARGO) clippy --package=cds_api_client --lib --bins --tests

distclean: clean
	$(Q) rm -r target

clean:
	$(Q) $(CARGO) clean
