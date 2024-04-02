.PHONY: trtool
trtool:
	go build -o trtool ./cmd/trtool

.PHONY: vet
vet:
	go vet ./...

.PHONY: fmt
fmt:
	go fmt ./...

.PHONY: test
test:
	go test ./...
