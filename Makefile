.PHONY: trtool
certtool:
	go build -o trtool ./cmd/trtool

.PHONY: vet
vet:
	go vet ./...

.PHONY: fmt
fmt:
	go fmt ./...
