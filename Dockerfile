ARG FIRST_FROM_IMAGE=registry.ci.openshift.org/openshift/release:golang-1.13
ARG SECOND_FROM_IOMAGE=registry.access.redhat.com/ubi8/ubi-minimal:latest
FROM ${FIRST_FROM_IMAGE} AS build-env

COPY . /src/

RUN cd /src && \
    make code/compile && \
    echo "Build SHA1: $(git rev-parse HEAD)" && \
    echo "$(git rev-parse HEAD)" > /src/BUILD_INFO

# final stage
FROM ${SECOND_FROM_IOMAGE}

##LABELS

RUN microdnf update && microdnf clean all && rm -rf /var/cache/yum/*

COPY --from=build-env /src/BUILD_INFO /src/BUILD_INFO
COPY --from=build-env /src/tmp/_output/bin/keycloak-operator /usr/local/bin

ENTRYPOINT ["/usr/local/bin/keycloak-operator"]
