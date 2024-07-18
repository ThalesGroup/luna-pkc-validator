# Luna PKC Validator

This project is part of the [Luna General Purpose HSMs](https://cpl.thalesgroup.com/encryption/hardware-security-modules/general-purpose-hsms) products suite, and more specifically of the [Luna Network HSM](https://cpl.thalesgroup.com/encryption/hardware-security-modules/network-hsms) product. 

## Introduction

This standalone Java application validates a PKC certificate chain built by a Luna Network HSM:

- It checks the certificate chain against the provided root CA from the trusted source.

- It checks that any provided Certificate Signing Request (CSR) matches the leaf certificate of the PKC chain.

The Luna root certificate can be retrieved [here](https://thalesdocs.com/gphsm/luna/7/docs/network/Content/admin_partition/confirm/confirm_hsm.htm).

Luna PKCs can be retrieved using the [CMU](https://www.thalesdocs.com/gphsm/luna/7/docs/network/Content/Utilities/cmu/cmu.htm) utility, using
- The [Luna Universal Client](https://thalesdocs.com/gphsm/luna/7/docs/network/Content/Utilities/Preface.htm), and esp.

  - The [Luna Shell (Lush)](https://thalesdocs.com/gphsm/luna/7/docs/network/Content/lunash/Preface.htm)

  - The [Luna client management tool (LunaCM)](https://thalesdocs.com/gphsm/luna/7/docs/network/Content/lunacm/Preface.htm)

- An existing initialized partition
  - See [here for the creation of the partition (on the appliance)](https://thalesdocs.com/gphsm/luna/7/docs/network/Content/lunacm/commands/partition/partition_create.htm))
  - See [here for the initialization of the partition (on the appliance)](https://thalesdocs.com/gphsm/luna/7/docs/network/Content/lunash/commands/partition/partition_init.htm)
  - See [here for the initialization of the "Crypto Officer" role (on the client end)](https://thalesdocs.com/gphsm/luna/7/docs/network/Content/lunacm/commands/role/role_init.htm)

- The "Crypto Officer" role password.

- An handle to a private signing key within this partition, as provided by the following kind of command (to be run on the client end, as an administrator/root user; select the slot that represents the existing initialized partition mentionned above if needed, and provide the "Crypto Officer" when requested):

  - For a RSA key pair:
```
cmu generateKeyPair -mech=pkcs -modulusBits=2048 -publicExp=65537 -sign=T -verify=T
```
  - For an ECC key pair:
```
cmu generateKeyPair -key ECDSA -curveType=3 -sign=T -verify=T
```

On the client end, as a "Crypto Officer", get the PKC using the handle of the private key created at the previous step (select the slot that represents the existing initialized partition mentionned above if needed, as well as the "Crypto Officer" password, the handle that corresponds to the private key to use and the name of the output file [e.g. 'pkc.p7b'] when requested):

```
cmu getpkc
```

A CSR can be created using the following command (select the slot that represents the existing initialized partition mentionned above if needed, and provide the "Crypto Officer" password, as well as the handle that corresponds to the private key to use and the name of the output file [e.g. 'test.csr'] when requested):):

```
cmu requestcertificate -C=CA -CN=test.com -E=test@test.com -L=Ottawa -O=Thales
```

## Build

Using Maven, with your own development environment including a JDK (11+) and Maven:

```
mvn clean compile assembly:single
```

Using Podman:

```
./build-with-podman.sh
```

Results are produced in the "target" directory.

The "luna-pkc-validator-1.0.0-jar-with-dependencies.jar" JAR  file is a self-sufficient Java archive that contains the validation function and the required dependencies (esp. the BouncyCastle library).

## Run

Refer to the usage documentation provided by the tool (running it without any parameter).

```
java -jar luna-pkc-validator.jar --pkc <pkc-file> {--ca <ca-file> | --req <req-file>}");
  --pkc  the PKC chain file to check.
  --ca   the Thales HSM Root CA file.
  --req  the Certificate Signing Request file.
```

Note: "luna-pkc-validator.jar" may need to be replaced with something like "luna-pkc-validator-1.0.0-jar-with-dependencies.jar" according to the way the JAR archive is produced by your Maven project.

## Test

### Check a PKC

Once the Luna root certificate(s) and a PKC file have been retrieved (e.g. "pkc.p7b"), the PKC can be checked with the following command:

- For RSA keys:

```
java -jar target/luna-pkc-validator-1.0.0-jar-with-dependencies.jar --pkc ./tests/rsa-pkc.p7b --ca ./tests/luna-rsa-root-certificate.pem
```

- For ECC keys:

```
java -jar target/luna-pkc-validator-1.0.0-jar-with-dependencies.jar --pkc ./tests/ecc-pkc.p7b --ca ./tests/luna-ecc-root-certificate.pem
```

### Check a CSR

A client certificate request can be checked with the following command:

- For RSA keys:

```
java -jar target/luna-pkc-validator-1.0.0-jar-with-dependencies.jar --pkc ./tests/rsa-pkc.p7b --req ./tests/rsa-test.csr

```

- For ECC keys:

```
java -jar target/luna-pkc-validator-1.0.0-jar-with-dependencies.jar --pkc ./tests/ecc-pkc.p7b --req ./tests/ecc-test.csr
```

## Contributing

If you are interested in contributing to this project, please read the [Contributing guide](CONTRIBUTING.md).

## License

This software is provided under a [permissive license](LICENSE).
