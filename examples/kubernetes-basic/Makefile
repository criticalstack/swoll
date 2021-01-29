REGISTRY=docker.io
USERNAME=errzey
APP_NAME=swoll-kube-test

binary:
	go build -ldflags="-extldflags=-static" -o kube-trace

build: binary
	docker build -t ${USERNAME}/${APP_NAME} . 
	
push:
	docker push ${USERNAME}/${APP_NAME}
	@echo "run: make deploy"

all: build binary
	@echo "run: make push"

deploy:
	kubectl apply -f deploy.yaml

uninstall:
	kubectl delete -f deploy.yaml

clean:
	rm ./kube-trace 
