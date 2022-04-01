all: server-cert.pem server-key.pem client-cert.pem client-key.pem

%-key.pem:
	openssl ecparam -out $@ -name secp384r1 -genkey

ca-cert.pem: ca-key.pem
	openssl req -x509 \
		-days 365 \
		-out ca-cert.pem \
		-key ca-key.pem \
		-subj "/O=pile/CN=pile CA"
	openssl x509 -in ca-cert.pem \
		-noout \
		-text

server-cert.pem: ca-cert.pem ca-key.pem server-req.pem
	openssl x509 -req \
		-in server-req.pem -days 365 \
		-CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial \
		-out server-cert.pem
	# remove the serial so that when called again openssl will generate a new random number
	rm -f ca-cert.srl
	openssl x509 -in server-cert.pem -noout -text

server-req.pem: server-key.pem
	openssl req -new \
		-key server-key.pem \
		-out server-req.pem \
		-subj "/O=pile/CN=piled"

client-cert.pem: ca-cert.pem ca-key.pem client-req.pem
	openssl x509 -req \
		-in client-req.pem \
		-days 60 \
		-CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial \
		-out client-cert.pem
	# remove the serial so that when called again openssl will generate a new random number
	rm -f ca-cert.srl
	openssl x509 -in client-cert.pem -noout -text

client-req.pem: client-key.pem
	openssl req -new \
		-key client-key.pem \
		-out client-req.pem \
		-subj "/O=pile/CN=pilec"

clean: 
	rm -f *.pem *.srl

.PHONY: clean
