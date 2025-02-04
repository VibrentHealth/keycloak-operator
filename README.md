# Keycloak Operator

At Vibrent, the `keycloak-operator` consumes 3 Custom Resource types (Keycloak, KeycloakRealm, KeycloakClient) and maintains Realm and Client configurations settings across a cluster.
It does not deploy and maintain the Keycloak servers directly. The `Keycloak` CRD is only used as a pointer to some Keycloak and contains admin credentials the operator can use on that instance.
This Operator implements the Operator SDK library, however because it's a "pre-1.0" version, you must view the legacy documentation (`v0.18.x`) ([link here](https://github.com/operator-framework/operator-sdk/blob/v0.18.x/website/content/en/docs/golang/quickstart.md)).

## Vibrent Confluence Documentation
The [Vibrent Confluence documentation for the Keycloak Operator](https://vibrenthealth.atlassian.net/wiki/spaces/AC/pages/1240864213/Keycloak+Operator)
contains a collection of background links from 3rd party sources, additional details on the high level design, and instruction for locally development and making Pull Requests.

## Vibrent Changelog
This repository began as a fork of the Work-In-Progress keycloak-operator from the community Keycloak team.
All customizations made on the fork are revisioned and documented below.
This fork was consistently rebased to bring in changes from upstream, until the parent repository was archived when Keycloak migrated away from Wildfly.

### Choose a new version for each Pull Request
For any change being made, and new version must be created in the Pull Request and a brief description should be included here.
> :warning: It looks the same, but this repo DOES NOT follow standard semantic versioning.

#### Example X.Y.Z
Instead of only be based on semantic versioning rules for "breaking change". The versioning scheme used here will increment the last numeral (`Z`) to indicate **this change is part of the same production release as the previous change**.
When starting a new production chance, increment the first or middle numeral (`X` or `Y`) depending on the scope of changes for the entire release, and reset the last numeral (`Z`) to `0`.

* The first numeral (`X`) represents a breaking change from the previous _production release_.
* The middle numeral (`Y`) should still always represent a new _production release_, but one that will not have breaking change.
* When a production release includes multiple Tickets or PRs, the last numeral (`Z`) is incremented for all Pull Requests after the first.

### Release History
#### Initial Release (1.6.X)
* Support for custom attributes on Realms 
* Realm update functionality
* Managing Realms on Unmanaged Keycloak instances
* Creation of a Helm Chart
* Realm deletion protection flag in KeycloakRealm CRD
* Support for merging new KeycloakClient with existing client: [AC-120153](https://vibrenthealth.atlassian.net/browse/AC-120153)
* Support for the Browser Security Headers Configuration in KeycloakRealm CRD: [AC-120343](https://vibrenthealth.atlassian.net/browse/AC-120343)
* Support for authentication flow bindings in the KeycloakRealm CRD
* Support for managing realm's required actions from the KeycloakRealm CRD: [AC-120810](https://vibrenthealth.atlassian.net/browse/AC-120810) and [AC-120811](https://vibrenthealth.atlassian.net/browse/AC-120811)
* Increase reconcile concurrency for client controller to 5: [AC-122514](https://vibrenthealth.atlassian.net/browse/AC-122514)
* Increase reconcile concurrency for client controller to 20: [AC-122819](https://vibrenthealth.atlassian.net/browse/AC-122819)
* Increase reconcile concurrency for client controller to 50: [AC-123079](https://vibrenthealth.atlassian.net/browse/AC-123079)

#### 1.7.X
* Update realm CRD with realm settings fields. Fields values are default, not set to anything: [AC-124726](https://vibrenthealth.atlassian.net/browse/AC-124726)
* Chart and init configuration to control operator SYNC_PERIOD, and concurrency for realm and client loops.
* New logic for updating "realm roles" in the KeycloakRealm reconcile logic.
* New logic for updating custom Authentication Flows used for participant login, registration, and password reset (Not all types of update are supported).

#### 1.8.X
* New logic for updating "realm clientScopes" and "realm requiredActions" in the KeycloakRealm reconcile logic.

#### 1.9.X
* Remove support for a managed Keycloak PodDisruptionBudget: [AC-144568](https://vibrenthealth.atlassian.net/browse/AC-144568)

#### 1.10.X
* Migrate docker repository and KC's dependency to the new Harbor instance.https://vibrenthealth.atlassian.net/browse/AC-150267

### Updating Custom Resource Definitions (CRD)
Currently, the CRDs in the Helm Chart are exact copies of the CRDs found in the /deploy/crds directory. Therefore, when updating a CRD you must replace the appropriate CRD found in /charts/keycloak-operator/crds with the updated CRD to ensure the Helm Chart contains the most current updates when deployed.

### GitHub Actions
GitHub actions are the primary CI mechanisms used to build and test the keycloak-operator. However, GitHub is not capable of publishing to our internal docker and helm repositories, so we also have a Jenkinsfile to handle that. See below.

1. ci.yml - ensures the tests pass by executing the following makefile commands: test/unit, test/e2e, and test/e2e-local-image
2. go.yml - ensures the code compiles by executing the following makefile command: code/compile
3. lint.yml - inspects the code by executing the following makefile commands: setup/linter and code/lint

### Jenkins Pipeline
The Jenkins pipeline is only responsible for publishing the docker container(s) and helm chart for the keycloak operator into our internal docker registry and help chart repository after the GitHub actions perform the other testing activities.

The pipeline will lint the Helm Chart anytime it is run, but will only publish the chart and docker image during a master branch build. Both the chart and docker image will be published to the vibrent-ops project.

Once the docker image has been published you will need to update the new image tag in the cluster-management values.yaml file to the new version of the keycloak-operator.

We have to do some tricky FROM statements in the Dockerfile because GitHub actions and Vibrent Jenkins pipelines cannot read from the same registries.

The pipeline has been updated to ignore the Dockerfiles during the 'Validate Docker Policies' step in the 'Compliance Stage'. The docker policy validation fails because the Dockerfile's FROM is dynamically built using an ARG (see Dockerfile below). Even though we use a trusted repository the validation fails stating we must use a trusted repository. 

### Dockerfile
The Dockerfile used to build the keycloak operator image supports the following two build arguments:

1. FIRST_FROM_IMAGE
2. SECOND_FROM_IMAGE

The original images, which are still used in the GitHub actions during local e2e testing (see test/e2e-local-image in the makefile), are from a repository that is not trusted by Vibrent's Jenkins pipeline. The Jenkins pipeline uses a Harbor proxy and pulls images from dockerhub. The dockerhub images are used by default if no build arguments are passed.

## Keycloak Documentation
All documentation below this point came from the original [keycloak operator repositiory](https://github.com/keycloak/keycloak-operator/blob/master/README.md) on May 3rd, 2021. There may be updates to the README that have not yet been merg3d with Vibrent's repository.

[![Build Status](https://travis-ci.org/keycloak/keycloak-operator.svg?branch=master)](https://travis-ci.org/keycloak/keycloak-operator)
[![Go Report Card](https://goreportcard.com/badge/github.com/keycloak/keycloak-operator)](https://goreportcard.com/report/github.com/keycloak/keycloak-operator)
[![Coverage Status](https://coveralls.io/repos/github/keycloak/keycloak-operator/badge.svg?branch=master)](https://coveralls.io/github/keycloak/keycloak-operator?branch=master)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)


## Help and Documentation

The official documentation might be found in the [here](https://www.keycloak.org/docs/latest/server_installation/index.html#_operator).

* [Keycloak documentation](https://www.keycloak.org/documentation.html)
* [User Mailing List](https://lists.jboss.org/mailman/listinfo/keycloak-user) - Mailing list for help and general questions about Keycloak
* [JIRA](https://issues.redhat.com/browse/KEYCLOAK-16220?jql=project%20%3D%20KEYCLOAK%20AND%20component%20%3D%20%22Container%20-%20Operator%22%20ORDER%20BY%20updated%20DESC) - Issue tracker for bugs and feature requests

## Reporting Security Vulnerabilities

If you've found a security vulnerability, please look at the [instructions on how to properly report it](http://www.keycloak.org/security.html)

## Reporting an issue

If you believe you have discovered a defect in the Keycloak Operator please open an issue in our [Issue Tracker](https://issues.jboss.org/projects/KEYCLOAK).
Please remember to provide a good summary, description as well as steps to reproduce the issue.

## Supported Custom Resources
| *CustomResourceDefinition*                                            | *Description*                                            |
| --------------------------------------------------------------------- | -------------------------------------------------------- |
| [Keycloak](./deploy/crds/keycloak.org_keycloaks_crd.yaml)             | Manages, installs and configures Keycloak on the cluster |
| [KeycloakRealm](./deploy/crds/keycloak.org_keycloakrealms_crd.yaml)   | Represents a realm in a keycloak server                  |
| [KeycloakClient](./deploy/crds/keycloak.org_keycloakclients_crd.yaml) | Represents a client in a keycloak server                 |
| [KeycloakBackup](./deploy/crds/keycloak.org_keycloakbackups_crd.yaml) | Manage Keycloak database backups                         |


## Deployment to a Kubernetes or Openshift cluster

The official documentation contains installation instruction for this Operator.

[Getting started with keycloak-operator on Openshift](https://www.keycloak.org/getting-started/getting-started-operator-openshift)

[Getting started with keycloak-operator on Kubernetes](https://www.keycloak.org/getting-started/getting-started-operator-kubernetes)

[Operator installation](https://www.keycloak.org/docs/latest/server_installation/index.html#_installing-operator)


## Developer Reference
*Note*: You will need a running Kubernetes or OpenShift cluster to use the Operator

1. Run `make cluster/prepare` # This will apply the necessary Custom Resource Definitions (CRDs) and RBAC rules to the clusters
2. Run `kubectl apply -f deploy/operator.yaml` # This will start the operator in the current namespace

### Creating Keycloak Instance
Once the CRDs and RBAC rules are applied and the operator is running. Use the examples from the operator.

1. Run `kubectl apply -f deploy/examples/keycloak/keycloak.yaml`

### Local Development
*Note*: You will need a running Kubernetes or OpenShift cluster to use the Operator

1.  clone this repo to `$GOPATH/src/github.com/keycloak/keycloak-operator`
2.  run `make setup/mod cluster/prepare`
3.  run `make code/run`
-- The above step will launch the operator on the local machine
-- To see how do debug the operator or how to deploy to a cluster, see below alternatives to step 3
4. In a new terminal run `make cluster/create/examples`
5. Optional: configure Ingress and DNS Resolver
   - minikube: \
     -- run `minikube addons enable ingress` \
     -- run `./hack/modify_etc_hosts.sh`
   - Docker for Mac: \
     -- run `kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-0.32.0/deploy/static/provider/cloud/deploy.yaml`
        (see also https://kubernetes.github.io/ingress-nginx/deploy/) \
     -- run `./hack/modify_etc_hosts.sh keycloak.local 127.0.0.1`
6. Run `make test/e2e`

To clean the cluster (Removes CRDs, CRs, RBAC and namespace)
1. run `make cluster/clean`

#### Alternative Step 2: Debug in Goland
Debug the operator in [Goland](https://www.jetbrains.com/go/)
1. go get -u github.com/go-delve/delve/cmd/dlv
2. Create new `Go Build` debug configuration
3. Change the properties to the following
```
* Name = Keycloak Operator
* Run Kind = File
* Files = <project full path>/cmd/manager/main.go
* Working Directory = <project full path>
* Environment = KUBERNETES_CONFIG=<kube config path>;WATCH_NAMESPACE=keycloak
```
3. Apply and click Debug Keycloak operator

#### Alternative Step 3: Debug in VSCode
Debug the operator in [VS Code](https://code.visualstudio.com/docs/languages/go)
1. go get -u github.com/go-delve/delve/cmd/dlv
2. Create new launch configuration, changing your kube config location
```json
{
  "name": "Keycloak Operator",
  "type": "go",
  "request": "launch",
  "mode": "auto",
  "program": "${workspaceFolder}/cmd/manager/main.go",
  "env": {
    "WATCH_NAMESPACE": "keycloak",
    "KUBERNETES_CONFIG": "<kube config path>"
  },
  "cwd": "${workspaceFolder}",
  "args": []
}
```
3. Debug Keycloak Operator

#### Alternative Step 3: Deploying to a Cluster
Deploy the operator into the running cluster
1. build image with `operator-sdk build <image registry>/<organisation>/keycloak-operator:<tag>`. e.g. `operator-sdk build quay.io/keycloak/keycloak-operator:test`
2. Change the `image` property in `deploy/operator.yaml` to the above full image path
3. run `kubectl apply -f deploy/operator.yaml -n <NAMESPACE>`

#### Alternative Step 6: Debug the e2e tests in Goland
Debug the e2e operator tests in [Goland](https://www.jetbrains.com/go/)
1. Set `Test kind` to `Package`
2. Set `Working directory` to `<your project directory>`
3. Set `Go tool arguments` to `-i -parallel=1`
4. Set `Program arguments` to `-root=<your project directory> -kubeconfig=<your home directory>/.kube/config -globalMan deploy/empty-init.yaml -namespacedMan deploy/empty-init.yaml -test.v -singleNamespace -localOperator -test.timeout 0`
5. Apply and click Debug Keycloak operator

### Makefile command reference
#### Operator Setup Management
| *Command*                      | *Description*                                                                                          |
| ------------------------------ | ------------------------------------------------------------------------------------------------------ |
| `make cluster/prepare`         | Creates the `keycloak` namespace, applies all CRDs to the cluster and sets up the RBAC files           |
| `make cluster/clean`           | Deletes the `keycloak` namespace, all `keycloak.org` CRDs and all RBAC files named `keycloak-operator` |
| `make cluster/create/examples` | Applies the example Keycloak and KeycloakRealm CRs                                                     |

#### Tests
| *Command*                    | *Description*                                               |
| ---------------------------- | ----------------------------------------------------------- |
| `make test/unit`             | Runs unit tests                                             |
| `make test/e2e`              | Runs e2e tests with operator ran locally                    |
| `make test/e2e-latest-image` | Runs e2e tests with latest available operator image running in the cluster |
| `make test/e2e-local-image`  | Runs e2e tests with local operator image running in the cluster |
| `make test/coverage/prepare` | Prepares coverage report from unit and e2e test results     |
| `make test/coverage`         | Generates coverage report                                   |

##### Running tests without cluster admin permissions
It's possible to deploy CRDs, roles, role bindings, etc. separately from running the tests:
1. Run `make cluster/prepare` as a cluster admin.
2. Run `make test/ibm-validation` as a user. The user needs the following permissions to run te tests:
```
apiGroups: ["", "apps", "keycloak.org"]
resources: ["persistentvolumeclaims", "deployments", "statefulsets", "keycloaks", "keycloakrealms", "keycloakusers", "keycloakclients", "keycloakbackups"]
verbs: ["*"]
```
Please bear in mind this is intended to be used for internal purposes as there's no guarantee it'll work without any issues.

#### Local Development
| *Command*                 | *Description*                                                                    |
| ------------------------- | -------------------------------------------------------------------------------- |
| `make setup`              | Runs `setup/mod` `setup/githooks` `code/gen`                                     |
| `make setup/githooks`     | Copys githooks from `./githooks` to `.git/hooks`                                 |
| `make setup/mod`          | Resets the main module's vendor directory to include all packages                |
| `make setup/operator-sdk` | Installs the operator-sdk                                                        |
| `make code/run`           | Runs the operator locally for development purposes                               |
| `make code/compile`       | Builds the operator                                                              |
| `make code/gen`           | Generates/Updates the operator files based on the CR status and spec definitions |
| `make code/check`         | Checks for linting errors in the code                                            |
| `make code/fix`           | Formats code using [gofmt](https://golang.org/cmd/gofmt/)                        |
| `make code/lint`          | Checks for linting errors in the code                                            |
| `make client/gen`         | Generates/Updates the clients bases on the CR status and spec definitions        |

#### Application Monitoring

NOTE: This functionality works only in OpenShift environment.

| *Command*                         | *Description*                                           |
| --------------------------------- | ------------------------------------------------------- |
| `make cluster/prepare/monitoring` | Installs and configures Application Monitoring Operator |

#### CI
| *Command*           | *Description*                                                              |
| ------------------- | -------------------------------------------------------------------------- |
| `make setup/travis` | Downloads operator-sdk, makes it executable and copys to `/usr/local/bin/` |

#### Components versions

All images used by the Operator might be controlled using dedicated Environmental Variables:

 | *Image*             | *Environment variable*          | *Default*                                                        |
 | ------------------- | ------------------------------- | ---------------------------------------------------------------- |
 | `Keycloak`          | `RELATED_IMAGE_KEYCLOAK`                | `quay.io/keycloak/keycloak:9.0.2`                                |
 | `RHSSO` for OpenJ9  | `RELATED_IMAGE_RHSSO_OPENJ9`            | `registry.redhat.io/rh-sso-7/sso74-openshift-rhel8:7.4-1`        |
 | `RHSSO` for OpenJDK | `RELATED_IMAGE_RHSSO_OPENJDK`           | `registry.redhat.io/rh-sso-7/sso74-openshift-rhel8:7.4-1`        |
 | Init container      | `RELATED_IMAGE_KEYCLOAK_INIT_CONTAINER` | `quay.io/keycloak/keycloak-init-container:master`                |
 | Backup container    | `RELATED_IMAGE_RHMI_BACKUP_CONTAINER`   | `quay.io/integreatly/backup-container:1.0.16`                    |
 | Postgresql          | `RELATED_IMAGE_POSTGRESQL`              | `registry.redhat.io/rhel8/postgresql-10:1`                       |

## Contributing

Before contributing to Keycloak Operator please read our [contributing guidelines](CONTRIBUTING.md).

## Other Keycloak Projects

* [Keycloak](https://github.com/keycloak/keycloak) - Keycloak Server and Java adapters
* [Keycloak Documentation](https://github.com/keycloak/keycloak-documentation) - Documentation for Keycloak
* [Keycloak QuickStarts](https://github.com/keycloak/keycloak-quickstarts) - QuickStarts for getting started with Keycloak
* [Keycloak Docker](https://github.com/jboss-dockerfiles/keycloak) - Docker images for Keycloak
* [Keycloak Node.js Connect](https://github.com/keycloak/keycloak-nodejs-connect) - Node.js adapter for Keycloak
* [Keycloak Node.js Admin Client](https://github.com/keycloak/keycloak-nodejs-admin-client) - Node.js library for Keycloak Admin REST API

## License

* [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)