FROM maven:3-openjdk-18-slim

LABEL \
    name="luna-pkcv-builder" \
    vendor="Thales" \
    version="1.0.0" \
    summary="Luna PKC Validator builder." \
    description="Set a development environment and build the application using a Maven POM.\
    The result is stored in the 'target' directory of the local user's home directory." \
    maintainer="Thales"

WORKDIR /luna

ADD  \
    ./pom.xml \ 
    ./

VOLUME /luna/src
VOLUME /luna/target

ENTRYPOINT [ "/usr/bin/mvn", "compile",  "assembly:single" ]
