## openconext-crypt-java

![coverage](.github/badges/jacoco.svg)
![branches coverage](.github/badges/branches.svg)

### [System Requirements](#system-requirements)

- Java 21
- Maven 3

First install Java 21 with a package manager
and then export the correct the `JAVA_HOME`. For example on macOS:

```bash
export JAVA_HOME=/Library/Java/JavaVirtualMachines/openjdk-21.jdk/Contents/Home/
```

### Usage 
Create private / public keypair (always use 2048 bit modulus)
```
openssl genrsa -traditional -out private_key.pem 2048
openssl rsa -pubout -in private_key.pem -out public_key.pem
```
Convert private key to pkcs8 format in order to import it from Java
```
openssl pkcs8 -topk8 -in private_key.pem -inform pem -out private_key_pkcs8.pem -outform pem -nocrypt
```

