GIT_COMMITSHA = $(shell git rev-parse HEAD)
IMAGE_NAME = "jaguar-mock"

all: test vet lint check-gofmt build

build:
	env GOOS=linux GOARCH=amd64 go build -mod=vendor -o jaguar-mock
	#go build -mod=vendor -o jaguar-mock

check-gofmt:
	scripts/check_gofmt.sh

lint:
	staticcheck

test:
	go test ./...

vet:
	go vet ./...

docker-build:
	docker build -t "$(IMAGE_NAME):latest" -t "$(IMAGE_NAME):$(GIT_COMMITSHA)" .
.PHONY: docker-build

docker-run:
	docker run --rm -it -p 12111-12112:12111-12112 "$(IMAGE_NAME):latest"
.PHONY: docker-run
