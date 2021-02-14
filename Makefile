IMAGE_NAME := "triaxis/cert-manager-webhook-hetzner"
IMAGE_TAG := "latest"

OUT := $(shell pwd)/_out

$(shell mkdir -p "$(OUT)")

verify:
	TEST_SRCDIR=$(PWD) go test -v -count=1 .

build:
	docker build -t "$(IMAGE_NAME):$(IMAGE_TAG)" .

.PHONY: rendered-manifest.yaml
rendered-manifest.yaml:
	helm template \
	    cert-manager-webhook-hetzner \
	    --set image.repository=$(IMAGE_NAME) \
	    --set image.tag=$(IMAGE_TAG) \
	    deploy/cert-manager-webhook-hetzner > "$(OUT)/rendered-manifest.yaml"
