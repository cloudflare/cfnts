cfssl gencert -config=int-config.json -ca=ca.pem -ca-key=ca-key.pem intermediate.json | cfssljson -bare intermediate
cfssl gencert -ca intermediate.pem -ca-key intermediate-key.pem test.json | cfssljson -bare tls
openssl pkcs8 -topk8 -nocrypt -in tls-key.pem -out tls-pkcs8.pem
cat tls.pem intermediate.pem ca.pem > chain.pem
