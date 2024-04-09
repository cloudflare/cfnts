openssl req -newkey rsa:4096 -keyout ca-key.pem -out ca.csr -days 3650 -nodes -subj "/C=US/ST=CA/L=San Francisco/CN=localhost"
openssl x509 -in ca.csr -out ca.pem -req -signkey ca-key.pem -days 3650
cfssl gencert -config=int-config.json -ca=ca.pem -ca-key=ca-key.pem intermediate.json | cfssljson -bare intermediate
cfssl gencert -config=test-config.json -ca intermediate.pem -ca-key intermediate-key.pem test.json | cfssljson -bare tls
openssl pkcs8 -topk8 -nocrypt -in tls-key.pem -out tls-pkcs8.pem
cat tls.pem intermediate.pem ca.pem > chain.pem
