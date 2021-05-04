# Keycloak Operator Chart

This chart is used to deploy the keycloak operator

## Usage
Vibrent created its own Helm Chart for the keycloak operator because one did not already exist. The CRDs and templates found in the chart were provided via the keycloak operator code and can be found in the deploy directory. The only changes to these objects were configuraing some of the values via the values.yaml file.

The official documentation for the keycloak operator is found [here](https://www.keycloak.org/docs/latest/server_installation/index.html#_operator).

## Supported Custom Resources
| *CustomResourceDefinition*                                            | *Description*                                            |
| --------------------------------------------------------------------- | -------------------------------------------------------- |
| [Keycloak](./deploy/crds/keycloak.org_keycloaks_crd.yaml)             | Manages, installs and configures Keycloak on the cluster |
| [KeycloakRealm](./deploy/crds/keycloak.org_keycloakrealms_crd.yaml)   | Represents a realm in a keycloak server                  |
| [KeycloakClient](./deploy/crds/keycloak.org_keycloakclients_crd.yaml) | Represents a client in a keycloak server                 |
| [KeycloakBackup](./deploy/crds/keycloak.org_keycloakbackups_crd.yaml) | Manage Keycloak database backups                         |


## WatchNamespace
The watchNamespace property found in the values.yaml file is a comma-delimited property used to determine which namespaces in a cluster the operator will be listening to. If it is an empty string it will listen to all namespaces and if it is populated it will only listen to the namespaces provided.