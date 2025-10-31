# create certificates for test-CA

#

* hint: use a console that provides input capabilities (not git bash in windows)
* create private key for CA:
  `openssl genrsa -aes256 -out test-roles-anywhere.key 2048`
* create certificate for CA:
  `openssl req -x509 -new -nodes -key test-roles-anywhere.key -sha256 -days 1826 -out test-roles-anywhere.crt -subj "/CN=Test CA/C=IN/ST=Test/L=Test/O=test"`
* create certificate for test client:
  `openssl req -new -nodes -out testClient.csr -newkey rsa:2048 -keyout testClient.key -subj "/CN=testClient/C=IN/ST=Test/L=Test/O=test"`
* sign the certificate:
  `openssl x509 -req -in testClient.csr -CA test-roles-anywhere.crt -CAkey test-roles-anywhere.key -CAcreateserial -out testClient.crt -days 730 -sha256 -extfile testClient.v3.ext`


