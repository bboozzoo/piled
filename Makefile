all: pilec piled certs

pilec: 
	go build -o pilec ./cmd/pile

piled:
	go build ./cmd/piled

certs:
	make -C certs


.PHONY: certs all
