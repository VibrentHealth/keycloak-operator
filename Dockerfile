# See README.md for how we alter the image repository based for Github actions and internal Jenkins pipeline
ARG FIRST_FROM_IMAGE=harbor.ssk8s.vibrenthealth.com/dockerhub/openshift/origin-release:golang-1.13
ARG SECOND_FROM_IMAGE=harbor.ssk8s.vibrenthealth.com/dockerhub/coolbeevip/ubi8-ubi-minimal:latest
FROM ${FIRST_FROM_IMAGE} AS build-env

COPY . /src/

RUN cd /src && \
    make code/compile && \
    echo "Build SHA1: $(git rev-parse HEAD)" && \
    echo "$(git rev-parse HEAD)" > /src/BUILD_INFO

# final stage
FROM ${SECOND_FROM_IMAGE}3067

##LABELS

RUN microdnf update && microdnf clean all && rm -rf /var/cache/yum/*

COPY --from=build-env /src/BUILD_INFO /src/BUILD_INFO
COPY --from=build-env /src/tmp/_output/bin/keycloak-operator /usr/local/bin

ENTRYPOINT ["/usr/local/bin/keycloak-operator"]
