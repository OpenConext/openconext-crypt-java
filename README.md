## openconext-crypt-java

![Coverage](.github/badges/jacoco.svg)
[![coverage](https://raw.githubusercontent.com/OpenConext/openconext-crypt-java/badges/jacoco.svg)](https://github.com/OpenConext/openconext-crypt-java/actions/workflows/build.yml) [![branches coverage](https://raw.githubusercontent.com/OpenConext/openconext-crypt-java/badges/branches.svg)](https://github.com/OpenConext/openconext-crypt-java/actions/workflows/actions.yml)

Create private / public keypair
```
openssl genrsa -traditional -out private_key.pem 2048
openssl rsa -pubout -in private_key.pem -out public_key.pem
```
Convert private key to pkcs8 format in order to import it from Java
```
openssl pkcs8 -topk8 -in private_key.pem -inform pem -out private_key_pkcs8.pem -outform pem -nocrypt
```