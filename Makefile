PACKAGES = $$(go list ./... | grep -v /vendor/)

vendor:
	go111module=on go mod vendor

fmt:
	go fmt $(PACKAGES)