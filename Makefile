all: pilec piled certs

pilec: 
	go build ./cmd/pilec

piled:
	go build ./cmd/piled

certs:
	make -C certs

clean:
	rm -f pilec piled
	make -C certs clean

.PHONY: certs all
