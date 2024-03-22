## openconext-crypt-java

![Coverage](.github/badges/jacoco.svg)

Create private / public keypair
```
openssl genrsa -traditional -out private_key.pem 2048
openssl rsa -pubout -in private_key.pem -out public_key.pem
```
Convert private key to pkcs8 format in order to import it from Java
```
openssl pkcs8 -topk8 -in private_key.pem -inform pem -out private_key_pkcs8.pem -outform pem -nocrypt
```