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

- An handle to a private signing key within this partition, as provided when using the following kind of command (to be run on the client end, as an administrator/root user):

```
cmu generateKeyPair -mech=pkcs -modulusBits=2048 -publicExp=65537
```

On the client end, as a "Crypto Officer", get the PKC using the handle of the private key created at the previous step.

```
cmu getpkc
```

A CSR can be created using the following command:

```
cmu requestcertificate -privatehandle=129 -publichandle=128 -C=CA -CN=test.com -E=test@test.com -L=Ottawa -O=Thales -OU=HSM -sha256withrsa -slot 0 -password userpin2 –outputfile=Test.CSR
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

Note: "luna-pkc-validator.jar" may need to be replaced with "luna-pkc-validator-1.0.0-jar-with-dependencies.jar" according to the way the JAR archive is produced by your Maven project.

## Test

Once the Luna root certificate (e.g. "safenet-root.pem") and a PKC file have been retrieved (e.g. "pkc.p7b"), the PKC can be checked with the following command:

safenet-root.pem can be used for validating RSA keys PKC. ECC keys need to be validated by the ECC_Manufacturing_Integrity_certificate

For RSA keys:

```
java -jar target/luna-pkc-validator-1.0.0-jar-with-dependencies.jar --pkc ./pkc.p7b --ca ./safenet-root.pem
```

For ECC keys:

```
java -jar target/luna-pkc-validator-1.0.0-jar-with-dependencies.jar --pkc ./pkc.p7b --ca ./ECC_Manufacturing_Integrity_certificate.cer
```

A client certificate request ("Test.CSR") can be checked with the following command:

```
java -jar target/luna-pkc-validator-1.0.0-jar-with-dependencies.jar --pkc ./pkc.p7b --req Test.CSR
```

## Contributing

If you are interested in contributing to this project, please read the [Contributing guide](CONTRIBUTING.md).

## License

This software is provided under a [permissive license](LICENSE).
