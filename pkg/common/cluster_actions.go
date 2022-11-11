package common

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	"github.com/keycloak/keycloak-operator/pkg/apis/keycloak/v1alpha1"
	"github.com/pkg/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/go-logr/logr"
)

var log = logf.Log.WithName("action_runner")
var vibrentClusterActionsLog = logf.Log.WithName("vibrent_action_runner")

const (
	authenticationConfigAlias string = "keycloak-operator-browser-redirector"
)

type ActionRunner interface {
	RunAll(desiredState DesiredClusterState) error
	Create(obj runtime.Object) error
	Update(obj runtime.Object) error
	Delete(obj runtime.Object) error
	CreateRealm(obj *v1alpha1.KeycloakRealm) error
	UpdateRealm(obj *v1alpha1.KeycloakRealm) error
	DeleteRealm(obj *v1alpha1.KeycloakRealm) error
	CreateClient(keycloakClient *v1alpha1.KeycloakClient, Realm string) error
	DeleteClient(keycloakClient *v1alpha1.KeycloakClient, Realm string) error
	UpdateClient(keycloakClient *v1alpha1.KeycloakClient, Realm string) error
	CreateClientRole(keycloakClient *v1alpha1.KeycloakClient, role *v1alpha1.RoleRepresentation, realm string) error
	UpdateClientRole(keycloakClient *v1alpha1.KeycloakClient, role, oldRole *v1alpha1.RoleRepresentation, realm string) error
	DeleteClientRole(keycloakClient *v1alpha1.KeycloakClient, role, Realm string) error
	CreateClientRealmScopeMappings(keycloakClient *v1alpha1.KeycloakClient, mappings *[]v1alpha1.RoleRepresentation, realm string) error
	DeleteClientRealmScopeMappings(keycloakClient *v1alpha1.KeycloakClient, mappings *[]v1alpha1.RoleRepresentation, realm string) error
	CreateClientClientScopeMappings(keycloakClient *v1alpha1.KeycloakClient, mappings *v1alpha1.ClientMappingsRepresentation, realm string) error
	DeleteClientClientScopeMappings(keycloakClient *v1alpha1.KeycloakClient, mappings *v1alpha1.ClientMappingsRepresentation, realm string) error
	UpdateClientDefaultClientScope(keycloakClient *v1alpha1.KeycloakClient, clientScope *v1alpha1.KeycloakClientScope, realm string) error
	DeleteClientDefaultClientScope(keycloakClient *v1alpha1.KeycloakClient, clientScope *v1alpha1.KeycloakClientScope, realm string) error
	UpdateClientOptionalClientScope(keycloakClient *v1alpha1.KeycloakClient, clientScope *v1alpha1.KeycloakClientScope, realm string) error
	DeleteClientOptionalClientScope(keycloakClient *v1alpha1.KeycloakClient, clientScope *v1alpha1.KeycloakClientScope, realm string) error
	CreateUser(obj *v1alpha1.KeycloakUser, realm string) error
	UpdateUser(obj *v1alpha1.KeycloakUser, realm string) error
	DeleteUser(id, realm string) error
	AssignRealmRole(obj *v1alpha1.KeycloakUserRole, userID, realm string) error
	RemoveRealmRole(obj *v1alpha1.KeycloakUserRole, userID, realm string) error
	AssignClientRole(obj *v1alpha1.KeycloakUserRole, clientID, userID, realm string) error
	RemoveClientRole(obj *v1alpha1.KeycloakUserRole, clientID, userID, realm string) error
	AddDefaultRoles(obj *[]v1alpha1.RoleRepresentation, defaultRealmRoleID, realm string) error
	DeleteDefaultRoles(obj *[]v1alpha1.RoleRepresentation, defaultRealmRoleID, realm string) error
	UpdateAuthenticationFlows(obj *v1alpha1.KeycloakRealm) error
	ApplyOverrides(obj *v1alpha1.KeycloakRealm) error
	UpdateRealmRoles(obj *v1alpha1.KeycloakRealm) error
	UpdateRealmRequiredActions(obj *v1alpha1.KeycloakRealm) error
	UpdateRealmClientScopes(obj *v1alpha1.KeycloakRealm) error
	Ping() error
}

type ClusterAction interface {
	Run(runner ActionRunner) (string, error)
}

type ClusterActionRunner struct {
	client         client.Client
	keycloakClient KeycloakInterface
	context        context.Context
	scheme         *runtime.Scheme
	cr             runtime.Object
}

const subscriberWebClient = "subscriber-web"

// Create an action runner to run kubernetes actions
func NewClusterActionRunner(context context.Context, client client.Client, scheme *runtime.Scheme, cr runtime.Object) ActionRunner {
	return &ClusterActionRunner{
		client:  client,
		context: context,
		scheme:  scheme,
		cr:      cr,
	}
}

// Create an action runner to run kubernetes and keycloak api actions
func NewClusterAndKeycloakActionRunner(context context.Context, client client.Client, scheme *runtime.Scheme, cr runtime.Object, keycloakClient KeycloakInterface) ActionRunner {
	return &ClusterActionRunner{
		client:         client,
		context:        context,
		scheme:         scheme,
		cr:             cr,
		keycloakClient: keycloakClient,
	}
}

func (i *ClusterActionRunner) RunAll(desiredState DesiredClusterState) error {
	for index, action := range desiredState {
		msg, err := action.Run(i)
		if err != nil {
			log.Info(fmt.Sprintf("(%5d) %10s %s : %s", index, "FAILED", msg, err))
			return err
		}
		log.Info(fmt.Sprintf("(%5d) %10s %s", index, "SUCCESS", msg))
	}

	return nil
}

func (i *ClusterActionRunner) Create(obj runtime.Object) error {
	err := controllerutil.SetControllerReference(i.cr.(v1.Object), obj.(v1.Object), i.scheme)
	if err != nil {
		return err
	}

	err = i.client.Create(i.context, obj)
	if err != nil {
		return err
	}

	return nil
}

func (i *ClusterActionRunner) Update(obj runtime.Object) error {
	err := controllerutil.SetControllerReference(i.cr.(v1.Object), obj.(v1.Object), i.scheme)
	if err != nil {
		return err
	}

	return i.client.Update(i.context, obj)
}

func (i *ClusterActionRunner) Delete(obj runtime.Object) error {
	return i.client.Delete(i.context, obj)
}

// Create a new realm using the keycloak api
func (i *ClusterActionRunner) CreateRealm(obj *v1alpha1.KeycloakRealm) error {
	if i.keycloakClient == nil {
		return errors.Errorf("cannot perform realm create when client is nil")
	}

	_, err := i.keycloakClient.CreateRealm(obj)
	return err
}

func (i *ClusterActionRunner) UpdateRealm(obj *v1alpha1.KeycloakRealm) error {
	if i.keycloakClient == nil {
		return errors.Errorf("cannot perform realm update when client is nil")
	}
	return i.keycloakClient.UpdateRealm(obj)
}

type Domain struct {
	ProgramCode string
	ProgramID   int
	URL         string
}

/**
* Call the endpoint configured in the client's APIDomian field. If the response can be parsed into a list of domains,
* return the domains formatted into two separate lists, contained in a custom Map object. All URLs are forced into lower
* case (see AC-120701)
*
* The Map object returned maps String keys "redirectUris" and "webOrigins" to String arrays. The arrays
* contain the formatted lists of URLs that need to be merged into the client object on the keycloak server.
**/
func retrieveDomains(obj *v1alpha1.KeycloakClient) map[string][]string {
	response, err := http.Get(obj.Spec.APIDomain)
	if err != nil {
		fmt.Print(err.Error())
	}
	responseData, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Error(err, "")
	}
	response.Body.Close()
	var domains []Domain
	err2 := json.Unmarshal(responseData, &domains)
	if err2 != nil {
		fmt.Println("error:", err2)
	}
	retrievedRedirectURIs := []string{}
	retrievedWebOrigins := []string{}
	for k := range domains {
		retrievedRedirectURIs = append(retrievedRedirectURIs, strings.ToLower(domains[k].URL+"/*"))
		retrievedWebOrigins = append(retrievedWebOrigins, strings.ToLower(domains[k].URL))
	}

	m := make(map[string][]string)
	m["redirectUris"] = retrievedRedirectURIs
	m["webOrigins"] = retrievedWebOrigins

	return m
}

func updateRedirectUrisWebOrigins(obj *v1alpha1.KeycloakClient) {
	if obj.Spec.Client.ClientID == subscriberWebClient && len(obj.Spec.APIDomain) != 0 {
		vibrentClusterActionsLog.Info(fmt.Sprintf("Client is %v. Merging program URLs into client.", subscriberWebClient))
		m := retrieveDomains(obj)
		completeListRedirectUris := obj.Spec.Client.RedirectUris
		apiEndpointRedirectUris := m["redirectUris"]
		for k := range apiEndpointRedirectUris {
			completeListRedirectUris = append(completeListRedirectUris, apiEndpointRedirectUris[k])
		}

		completeListWebOrigins := obj.Spec.Client.WebOrigins
		apiEndpointWebOrigins := m["webOrigins"]
		for i := range apiEndpointWebOrigins {
			completeListWebOrigins = append(completeListWebOrigins, apiEndpointWebOrigins[i])
		}

		obj.Spec.Client.RedirectUris = completeListRedirectUris
		obj.Spec.Client.WebOrigins = completeListWebOrigins
	}
}

func (i *ClusterActionRunner) CreateClient(obj *v1alpha1.KeycloakClient, realm string) error {
	vibrentClusterActionsLog.Info(fmt.Sprintf("Performing CreateClient action for %v/%v - obj.Spec.Client.ID: %v", realm, obj.Spec.Client.ClientID, obj.Spec.Client.ID))
	updateRedirectUrisWebOrigins(obj) // AC-118431

	if i.keycloakClient == nil {
		return errors.Errorf("cannot perform client create when client is nil")
	}

	uid, err := i.keycloakClient.CreateClient(obj.Spec.Client, realm)

	if err != nil {
		vibrentClusterActionsLog.Info(fmt.Sprintf("Error during CreateClient action for %v/%v - Error is: %v", realm, obj.Spec.Client.ClientID, err))
		return err
	}

	vibrentClusterActionsLog.Info(fmt.Sprintf("Successfully completed CreateClient action for %v/%v - returned uid: %v", realm, obj.Spec.Client.ClientID, uid))
	obj.Spec.Client.ID = uid

	// This client update request commits the CR modifications to the resource in the cluster.
	// Here in CreateClient, it is intended to preserve the uid of the newly created client on the Keycloak Server, but
	// it will also persist any redirect or origin URLs that come from a configured API endpoint. This will make them
	// unremovable without a deployment (minor issue).
	//
	// By default, the operator does not do this for UpdateClient. Currently there isn't an explicit need for us to add it.
	return i.client.Update(i.context, obj)
}

func (i *ClusterActionRunner) UpdateClient(obj *v1alpha1.KeycloakClient, realm string) error {
	vibrentClusterActionsLog.Info(fmt.Sprintf("Performing UpdateClient action for %v/%v - obj.Spec.Client.ID: %v", realm, obj.Spec.Client.ClientID, obj.Spec.Client.ID))
	updateRedirectUrisWebOrigins(obj) // AC-118431

	if i.keycloakClient == nil {
		return errors.Errorf("cannot perform client update when client is nil")
	}

	err := i.keycloakClient.UpdateClient(obj.Spec.Client, realm)

	if err != nil {
		vibrentClusterActionsLog.Info(fmt.Sprintf("Error during UpdateClient action for %v/%v - Error is: %v", realm, obj.Spec.Client.ClientID, err))
		return err
	}

	vibrentClusterActionsLog.Info(fmt.Sprintf("Successfully completed UpdateClient action for %v/%v", realm, obj.Spec.Client.ClientID))

	// This would persist the results of `updateRedirectUrisWebOrigin(obj)` in the CR on the cluster. Would be consistent
	// with CreateClient, but would require additional testing.
	// return i.client.Update(i.context, obj)

	return err // will be nil
}

func (i *ClusterActionRunner) CreateClientRole(obj *v1alpha1.KeycloakClient, role *v1alpha1.RoleRepresentation, realm string) error {
	if i.keycloakClient == nil {
		return errors.Errorf("cannot perform client role create when client is nil")
	}
	_, err := i.keycloakClient.CreateClientRole(obj.Spec.Client.ID, role, realm)
	return err
}

func (i *ClusterActionRunner) UpdateClientRole(obj *v1alpha1.KeycloakClient, role, oldRole *v1alpha1.RoleRepresentation, realm string) error {
	if i.keycloakClient == nil {
		return errors.Errorf("cannot perform client role update when client is nil")
	}
	return i.keycloakClient.UpdateClientRole(obj.Spec.Client.ID, role, oldRole, realm)
}

func (i *ClusterActionRunner) DeleteClientRole(obj *v1alpha1.KeycloakClient, role, realm string) error {
	if i.keycloakClient == nil {
		return errors.Errorf("cannot perform client role delete when client is nil")
	}
	return i.keycloakClient.DeleteClientRole(obj.Spec.Client.ID, role, realm)
}

func (i *ClusterActionRunner) CreateClientRealmScopeMappings(keycloakClient *v1alpha1.KeycloakClient, mappings *[]v1alpha1.RoleRepresentation, realm string) error {
	if i.keycloakClient == nil {
		return errors.Errorf("cannot perform client realm scope create when client is nil")
	}
	return i.keycloakClient.CreateClientRealmScopeMappings(keycloakClient.Spec.Client, mappings, realm)
}

func (i *ClusterActionRunner) DeleteClientRealmScopeMappings(keycloakClient *v1alpha1.KeycloakClient, mappings *[]v1alpha1.RoleRepresentation, realm string) error {
	if i.keycloakClient == nil {
		return errors.Errorf("cannot perform client realm scope delete when client is nil")
	}
	return i.keycloakClient.DeleteClientRealmScopeMappings(keycloakClient.Spec.Client, mappings, realm)
}

func (i *ClusterActionRunner) CreateClientClientScopeMappings(keycloakClient *v1alpha1.KeycloakClient, mappings *v1alpha1.ClientMappingsRepresentation, realm string) error {
	if i.keycloakClient == nil {
		return errors.Errorf("cannot perform client client scope create when client is nil")
	}
	return i.keycloakClient.CreateClientClientScopeMappings(keycloakClient.Spec.Client, mappings, realm)
}

func (i *ClusterActionRunner) DeleteClientDefaultClientScope(keycloakClient *v1alpha1.KeycloakClient, clientScope *v1alpha1.KeycloakClientScope, realm string) error {
	if i.keycloakClient == nil {
		return errors.Errorf("cannot perform client default client scope delete when client is nil")
	}
	return i.keycloakClient.DeleteClientDefaultClientScope(keycloakClient.Spec.Client, clientScope, realm)
}

func (i *ClusterActionRunner) UpdateClientDefaultClientScope(keycloakClient *v1alpha1.KeycloakClient, clientScope *v1alpha1.KeycloakClientScope, realm string) error {
	if i.keycloakClient == nil {
		return errors.Errorf("cannot perform client default client scope create when client is nil")
	}
	return i.keycloakClient.UpdateClientDefaultClientScope(keycloakClient.Spec.Client, clientScope, realm)
}

func (i *ClusterActionRunner) DeleteClientOptionalClientScope(keycloakClient *v1alpha1.KeycloakClient, clientScope *v1alpha1.KeycloakClientScope, realm string) error {
	if i.keycloakClient == nil {
		return errors.Errorf("cannot perform client optional client scope delete when client is nil")
	}
	return i.keycloakClient.DeleteClientOptionalClientScope(keycloakClient.Spec.Client, clientScope, realm)
}

func (i *ClusterActionRunner) UpdateClientOptionalClientScope(keycloakClient *v1alpha1.KeycloakClient, clientScope *v1alpha1.KeycloakClientScope, realm string) error {
	if i.keycloakClient == nil {
		return errors.Errorf("cannot perform client optional client scope create when client is nil")
	}
	return i.keycloakClient.UpdateClientOptionalClientScope(keycloakClient.Spec.Client, clientScope, realm)
}

func (i *ClusterActionRunner) DeleteClientClientScopeMappings(keycloakClient *v1alpha1.KeycloakClient, mappings *v1alpha1.ClientMappingsRepresentation, realm string) error {
	if i.keycloakClient == nil {
		return errors.Errorf("cannot perform client client scope delete when client is nil")
	}
	return i.keycloakClient.DeleteClientClientScopeMappings(keycloakClient.Spec.Client, mappings, realm)
}

// Delete a realm using the keycloak api
func (i *ClusterActionRunner) DeleteRealm(obj *v1alpha1.KeycloakRealm) error {
	if i.keycloakClient == nil {
		return errors.Errorf("cannot perform realm delete when client is nil")
	}
	return i.keycloakClient.DeleteRealm(obj.Spec.Realm.Realm)
}

func (i *ClusterActionRunner) DeleteClient(obj *v1alpha1.KeycloakClient, realm string) error {
	if i.keycloakClient == nil {
		return errors.Errorf("cannot perform client delete when client is nil")
	}
	return i.keycloakClient.DeleteClient(obj.Spec.Client.ID, realm)
}

func (i *ClusterActionRunner) CreateUser(obj *v1alpha1.KeycloakUser, realm string) error {
	if i.keycloakClient == nil {
		return errors.Errorf("cannot perform user create when client is nil")
	}

	// Create the user
	uid, err := i.keycloakClient.CreateUser(&obj.Spec.User, realm)
	if err != nil {
		return err
	}

	// Update newly created user with its uid
	obj.Spec.User.ID = uid
	return i.client.Update(i.context, obj)
}

func (i *ClusterActionRunner) UpdateUser(obj *v1alpha1.KeycloakUser, realm string) error {
	if i.keycloakClient == nil {
		return errors.Errorf("cannot perform user update when client is nil")
	}

	err := i.keycloakClient.UpdateUser(&obj.Spec.User, realm)
	if err != nil {
		return err
	}

	return nil
}

func (i *ClusterActionRunner) DeleteUser(id, realm string) error {
	if i.keycloakClient == nil {
		return errors.Errorf("cannot perform user delete when client is nil")
	}
	return i.keycloakClient.DeleteUser(id, realm)
}

// Check if Keycloak is available
func (i *ClusterActionRunner) Ping() error {
	if i.keycloakClient == nil {
		return errors.Errorf("cannot perform keycloak ping when client is nil")
	}
	return i.keycloakClient.Ping()
}

func (i *ClusterActionRunner) AssignRealmRole(obj *v1alpha1.KeycloakUserRole, userID, realm string) error {
	if i.keycloakClient == nil {
		return errors.Errorf("cannot perform role assign when client is nil")
	}

	_, err := i.keycloakClient.CreateUserRealmRole(obj, realm, userID)
	return err
}

func (i *ClusterActionRunner) RemoveRealmRole(obj *v1alpha1.KeycloakUserRole, userID, realm string) error {
	if i.keycloakClient == nil {
		return errors.Errorf("cannot perform role remove when client is nil")
	}
	return i.keycloakClient.DeleteUserRealmRole(obj, realm, userID)
}

func (i *ClusterActionRunner) AssignClientRole(obj *v1alpha1.KeycloakUserRole, clientID, userID, realm string) error {
	if i.keycloakClient == nil {
		return errors.Errorf("cannot perform role assign when client is nil")
	}

	_, err := i.keycloakClient.CreateUserClientRole(obj, realm, clientID, userID)
	return err
}

func (i *ClusterActionRunner) RemoveClientRole(obj *v1alpha1.KeycloakUserRole, clientID, userID, realm string) error {
	if i.keycloakClient == nil {
		return errors.Errorf("cannot perform role remove when client is nil")
	}
	return i.keycloakClient.DeleteUserClientRole(obj, realm, clientID, userID)
}

func (i *ClusterActionRunner) AddDefaultRoles(obj *[]v1alpha1.RoleRepresentation, defaultRealmRoleID, realm string) error {
	if i.keycloakClient == nil {
		return errors.Errorf("cannot perform default role add when client is nil")
	}
	return i.keycloakClient.AddRealmRoleComposites(realm, defaultRealmRoleID, obj)
}

func (i *ClusterActionRunner) DeleteDefaultRoles(obj *[]v1alpha1.RoleRepresentation, defaultRealmRoleID, realm string) error {
	if i.keycloakClient == nil {
		return errors.Errorf("cannot perform default role delete when client is nil")
	}
	return i.keycloakClient.DeleteRealmRoleComposites(realm, defaultRealmRoleID, obj)
}

// Delete a realm using the keycloak api
func (i *ClusterActionRunner) ApplyOverrides(obj *v1alpha1.KeycloakRealm) error {
	if i.keycloakClient == nil {
		return errors.Errorf("cannot perform realm configure when client is nil")
	}

	for _, override := range obj.Spec.RealmOverrides {
		err := i.configureBrowserRedirector(override.IdentityProvider, override.ForFlow, obj)
		if err != nil {
			return err
		}
	}

	return nil
}

// Configure realm roles.
func (i *ClusterActionRunner) UpdateRealmRoles(obj *v1alpha1.KeycloakRealm) error {
	if i.keycloakClient == nil {
		return errors.Errorf("cannot perform realm roles configure when client is nil")
	}

	return i.configureRealmRoles(obj)
}

// Configure realm client scopes.
func (i *ClusterActionRunner) UpdateRealmClientScopes(obj *v1alpha1.KeycloakRealm) error {
	if i.keycloakClient == nil {
		return errors.Errorf("cannot perform realm client scopes configure when client is nil")
	}

	return i.configureRealmClientScopes(obj)
}

// Configure realm required actions.
func (i *ClusterActionRunner) UpdateRealmRequiredActions(obj *v1alpha1.KeycloakRealm) error {
	if i.keycloakClient == nil {
		return errors.Errorf("cannot perform realm required actions configure when client is nil")
	}

	return i.configureRealmRequiredActions(obj)
}

func (i *ClusterActionRunner) UpdateAuthenticationFlows(obj *v1alpha1.KeycloakRealm) error {
	if i.keycloakClient == nil {
		return errors.Errorf("cannot perform authentication flow configure when client is nil")
	}

	return i.configureAuthenticationFlows(obj)
}

/**
* "UPDATE" BUSINESS LOGIC FOR COMPLEX COMPONENTS
**/

func (i *ClusterActionRunner) configureBrowserRedirector(provider, flow string, obj *v1alpha1.KeycloakRealm) error {
	realmName := obj.Spec.Realm.Realm
	authenticationExecutionInfo, err := i.keycloakClient.ListAuthenticationExecutionsForFlow(flow, realmName)
	if err != nil {
		return err
	}

	authenticationConfigID := ""
	redirectorExecutionID := ""
	for _, execution := range authenticationExecutionInfo {
		if execution.ProviderID == "identity-provider-redirector" {
			authenticationConfigID = execution.AuthenticationConfig
			redirectorExecutionID = execution.ID
		}
	}
	if redirectorExecutionID == "" {
		return errors.Errorf("'identity-provider-redirector' was not found in the list of executions of the 'browser' flow")
	}

	var authenticatorConfig *v1alpha1.AuthenticatorConfig
	if authenticationConfigID != "" {
		authenticatorConfig, err = i.keycloakClient.GetAuthenticatorConfig(authenticationConfigID, realmName)
		if err != nil {
			return err
		}
	}

	if authenticatorConfig == nil && provider != "" {
		config := &v1alpha1.AuthenticatorConfig{
			Alias:  authenticationConfigAlias,
			Config: map[string]string{"defaultProvider": provider},
		}

		if _, err := i.keycloakClient.CreateAuthenticatorConfig(config, realmName, redirectorExecutionID); err != nil {
			return err
		}
		return nil
	}

	return nil
}

func (i *ClusterActionRunner) configureRealmRequiredActions(obj *v1alpha1.KeycloakRealm) error {
  realmName := obj.Spec.Realm.Realm
  actionLogger := log.WithValues("Request.Namespace", obj.Namespace, "Request.Name", obj.Name, "Realm.Name", realmName)

  // Fetch realm required actions from Keycloak API
  actualRealmRequiredActions, err := i.keycloakClient.ListRealmRequiredActions(realmName)
  if err != nil {
    return err
  }

  actualRealmRequiredActionsAliases, actualRealmRequiredActionsMap := prepareActualRealmRequiredActions(actualRealmRequiredActions)
	desiredRealmRequiredActionsAliases, desiredRealmRequiredActionsMap := prepareDesiredRealmRequiredActions(obj)

  requiredActionsToRemove := difference(actualRealmRequiredActionsAliases, desiredRealmRequiredActionsAliases)
  requiredActionsToAdd := difference(desiredRealmRequiredActionsAliases, actualRealmRequiredActionsAliases)
  requiredActionsToCompare := difference(union(actualRealmRequiredActionsAliases, desiredRealmRequiredActionsAliases), append(requiredActionsToAdd))

  actionLogger.Info(fmt.Sprintf("[REALM REQUIRED ACTION] Adding: %v, Comparing: %v", requiredActionsToAdd, requiredActionsToCompare))

  // Do additions
  for _, alias := range requiredActionsToAdd {
    actionLogger.Info(fmt.Sprintf("[REALM REQUIRED ACTION REGISTRATION] Registering new realm required action %v", alias))
    err = i.keycloakClient.RegisterRealmRequiredAction(desiredRealmRequiredActionsMap[alias], realmName)
    if err != nil {
      requiredActionJSON, jsonerr := json.Marshal(desiredRealmRequiredActionsMap[alias])
      if jsonerr != nil {
        actionLogger.Info(fmt.Sprintf("[REALM REQUIRED ACTION REGISTRATION - ERROR] Registering new realm required action %v, and unable to marshal JSON.", alias))
        return err
      }
      actionLogger.Info(fmt.Sprintf("[REALM ROLE REGISTRATION - ERROR] Creating new realm role %v", requiredActionJSON))
      return err
    }
  }

  // If additions were made, rebuild the actual realm list. In case new roles are used in composites.
  if len(requiredActionsToAdd) > 0 {
    actionLogger.Info("Required actions were added, rebuild action list.")
    actualRealmRequiredActions, err = i.keycloakClient.ListRealmRequiredActions(realmName)
    if err != nil {
      return err
    }
    _, actualRealmRequiredActionsMap = prepareActualRealmRequiredActions(actualRealmRequiredActions)
  }

  // Do comparisons
  for _, alias := range requiredActionsToCompare {
    err = i.compareAndUpdateRealmRequiredRole(realmName, desiredRealmRequiredActionsMap[alias], actualRealmRequiredActionsMap[alias], actualRealmRequiredActionsMap, actionLogger)
    if err != nil {
      return err
    }
  }

  // Do deletions
  for _, alias := range requiredActionsToRemove {
    actionLogger.Info(fmt.Sprintf("[REALM REQUIRED ACTION DELETION - ERROR] Deleting realm required action %v. Deletion of realm required actions is not supported.", alias))
  }

  return nil
}

func (i *ClusterActionRunner) configureRealmClientScopes(obj *v1alpha1.KeycloakRealm) error {
  realmName := obj.Spec.Realm.Realm
	actionLogger := log.WithValues("Request.Namespace", obj.Namespace, "Request.Name", obj.Name, "Realm.Name", realmName)

	// Fetch realm roles from Keycloak API
	actualRealmClientScopes, err := i.keycloakClient.ListRealmClientScopes(realmName)
	if err != nil {
		return err
	}

	// Return a map of role names to RoleRepresentation objects, and the key set as a list.
	actualRealmClientScopeNames, actualRealmClientScopeMap := prepareActualRealmClientScopes(actualRealmClientScopes)
	desiredRealmClientScopeNames, desiredRealmClientScopeMap := prepareDesiredRealmClientScopes(obj)

	clientScopesToRemove := difference(actualRealmClientScopeNames, desiredRealmClientScopeNames)
	clientScopesToAdd := difference(desiredRealmClientScopeNames, actualRealmClientScopeNames)
	clientScopesToCompare := difference(union(actualRealmClientScopeNames, desiredRealmClientScopeNames), append(clientScopesToAdd, clientScopesToRemove...))

	actionLogger.Info(fmt.Sprintf("[REALM CLIENT SCOPE] Adding: %v, Comparing: %v, Removing: %v", clientScopesToAdd, clientScopesToCompare, clientScopesToRemove))

	// Do additions
	for _, name := range clientScopesToAdd {
		actionLogger.Info(fmt.Sprintf("[REALM CLIENT SCOPE CREATION] Creating new realm client scope %v", name))
		err = i.keycloakClient.CreateRealmClientScope(desiredRealmClientScopeMap[name], realmName)
		if err != nil {
			clientScopeJSON, jsonerr := json.Marshal(desiredRealmClientScopeMap[name])
			if jsonerr != nil {
				actionLogger.Info(fmt.Sprintf("[REALM CLIENT SCOPE CREATION - ERROR] Creating new realm client scope %v, and unable to marshal JSON.", name))
				return err
			}
			actionLogger.Info(fmt.Sprintf("[REALM CLIENT SCOPE CREATION - ERROR] Creating new realm client scope %v", clientScopeJSON))
			return err
		}
	}

	// If additions were made, rebuild the actual realm list.
	if len(clientScopesToAdd) > 0 {
		actionLogger.Info("Client scopes were added, rebuild client scope list.")
		actualRealmClientScopes, err = i.keycloakClient.ListRealmClientScopes(realmName)
		if err != nil {
			return err
		}
		_, actualRealmClientScopeMap = prepareActualRealmClientScopes(actualRealmClientScopes)
	}

	// Do comparisons
// 	for _, name := range clientScopesToCompare {
// 		err = i.compareAndUpdateRealmClientScope(realmName, desiredRealmClientScopeMap[name], actualRealmClientScopeMap[name], actualRealmClientScopeMap, actionLogger)
// 		if err != nil {
// 			return err
// 		}
// 	}

	// Do deletions
	for _, name := range clientScopesToRemove {
		actionLogger.Info(fmt.Sprintf("[REALM CLIENT SCOPE DELETION] Deleting realm client scope %v.", name))
		actionLogger.Info(fmt.Sprintf("[REALM CLIENT SCOPE DELETION] Deleting realm client scope ID %v.", actualRealmClientScopeMap[name].ID))
		err = i.keycloakClient.DeleteRealmClientScope(realmName, actualRealmClientScopeMap[name].ID)
		if err != nil {
			actionLogger.Info(fmt.Sprintf("[REALM CLIENT SCOPE DELETION - ERROR] Unable to delete existing realm client scope %v.", name))
			return err
		}
	}

  return nil
}

/**
 * Vibrent logic to compare and issue updates to Realm Roles
 *
 * Supported Changes:
 *   * Creation of new realm roles (cannot have reserved name)
 *   * Deletion of exsting realm roles (cannot delete reserved roles)
 *   * Adding or removing composites to a new or existing realm role
 *
 * Unsupported:
 *   * Any management of the reserved roles, which are auto-generated: `offline_access`, `uma_authorization`, and the default role, named `default-roles-<realmname>`
 *     * Adding/removing composites to the default role IS supported, through `spec.realm.defaultRoles` instead of here.
 *     * You can also add/ reserved roles as composites to other roles.
 *   * Configuration of client roles or the roles.client.additionalProperties attribute.
**/
func (i *ClusterActionRunner) configureRealmRoles(obj *v1alpha1.KeycloakRealm) error {
	realmName := obj.Spec.Realm.Realm
	actionLogger := log.WithValues("Request.Namespace", obj.Namespace, "Request.Name", obj.Name, "Realm.Name", realmName)

	ignoredRolesList := []string{"offline_access", "uma_authorization", "default-roles-" + strings.ToLower(realmName)}

	// Fetch realm roles from Keycloak API
	actualRealmRoles, err := i.keycloakClient.ListRealmRoles(realmName)
	if err != nil {
		return err
	}

	// Return a map of role names to RoleRepresentation objects, and the key set as a list.
	actualRealmRoleNames, actualRealmRoleMap := prepareActualRealmRoles(actualRealmRoles, ignoredRolesList)
	desiredRealmRoleNames, desiredRealmRoleMap := prepareDesiredRealmRoles(obj, ignoredRolesList)

	rolesToRemove := difference(actualRealmRoleNames, desiredRealmRoleNames)
	rolesToAdd := difference(desiredRealmRoleNames, actualRealmRoleNames)
	rolesToCompare := difference(union(actualRealmRoleNames, desiredRealmRoleNames), append(rolesToAdd, rolesToRemove...))

	actionLogger.Info(fmt.Sprintf("[REALM ROLE] Adding: %v, Comparing: %v, Removing: %v", rolesToAdd, rolesToCompare, rolesToRemove))

	// Do additions
	for _, name := range rolesToAdd {
		actionLogger.Info(fmt.Sprintf("[REALM ROLE CREATION] Creating new realm role %v", name))
		err = i.keycloakClient.CreateRealmRole(desiredRealmRoleMap[name], realmName)
		if err != nil {
			roleJSON, jsonerr := json.Marshal(desiredRealmRoleMap[name])
			if jsonerr != nil {
				actionLogger.Info(fmt.Sprintf("[REALM ROLE CREATION - ERROR] Creating new realm role %v, and unable to marshal JSON.", name))
				return err
			}
			actionLogger.Info(fmt.Sprintf("[REALM ROLE CREATION - ERROR] Creating new realm role %v", roleJSON))
			return err
		}
	}

	// If additions were made, rebuild the actual realm list. In case new roles are used in composites.
	if len(rolesToAdd) > 0 {
		actionLogger.Info("Roles were added, rebuild role list.")
		actualRealmRoles, err = i.keycloakClient.ListRealmRoles(realmName)
		if err != nil {
			return err
		}
		_, actualRealmRoleMap = prepareActualRealmRoles(actualRealmRoles, ignoredRolesList)
	}

	// Do comparisons
	for _, name := range rolesToCompare {
		err = i.compareAndUpdateRealmRole(realmName, desiredRealmRoleMap[name], actualRealmRoleMap[name], actualRealmRoleMap, actionLogger)
		if err != nil {
			return err
		}
	}

	// Do deletions
	for _, name := range rolesToRemove {
		actionLogger.Info(fmt.Sprintf("[REALM ROLE DELETION] Deleting realm role %v. Will be unassigned from all users.", name))
		err = i.keycloakClient.DeleteRealmRole(realmName, actualRealmRoleMap[name].ID)
		if err != nil {
			actionLogger.Info(fmt.Sprintf("[REALM ROLE DELETION - ERROR] Unable to delete existing realm role %v.", name))
			return err
		}
	}

	return nil
}

func (i *ClusterActionRunner) compareAndUpdateRealmRequiredRole(realmName string, dRequiredAction *v1alpha1.KeycloakAPIRequiredAction, aRequiredAction *v1alpha1.KeycloakAPIRequiredAction, allActualRequiredActionsMap map[string]*v1alpha1.KeycloakAPIRequiredAction, actionLogger logr.Logger) error {
  roleLogger := actionLogger.WithValues("Realm.RequiredActions", dRequiredAction.Alias)

  if dRequiredAction.DefaultAction != aRequiredAction.DefaultAction ||  dRequiredAction.Enabled != aRequiredAction.Enabled {
    roleLogger.Info(fmt.Sprintf("[REALM REQUIRED ACTION CHANGE] Update generic values of realm required action %v.", aRequiredAction.Alias))
    err := i.keycloakClient.UpdateRealmRequiredAction(dRequiredAction, realmName, aRequiredAction.Alias)
    if err != nil {
      requiredActionJSON, jsonerr := json.Marshal(*dRequiredAction)
      if jsonerr != nil {
        roleLogger.Info(fmt.Sprintf("[REALM REQUIRED ACTION - ERROR] Unable to update realm required action %v, and unable to marshal JSON.", aRequiredAction.Alias))
        return err
      }
      roleLogger.Info(fmt.Sprintf("[REALM REQUIRED ACTION CHANGE - ERROR] Unable to update realm required action %s", requiredActionJSON))
      return err
    }
  }
  return nil
}

func (i *ClusterActionRunner) compareAndUpdateRealmClientScope(realmName string, dClientScope *v1alpha1.KeycloakClientScope, aClientScope *v1alpha1.KeycloakClientScope, allActualClientScopesMap map[string]*v1alpha1.KeycloakClientScope, actionLogger logr.Logger) error {
  return nil
}

/**
 * Compare a realm role's desired and actual state and issue updates if necessary.
 *
 * ARGS
 * * realmName string, used by keycloakClient for http requests
 * * dRole RoleRepresentation: The desired state for comparison, parsed from the CR definition
 * * aRole RoleRepresentation: The actual state for comparison, queried from the Keycloak API
 * * allActualRolesMap map[string]*v1alpha1.RoleRepresentation: Map contains all current roles queried from the Keycloak API, including roles just created in this reconciliation. Keys are role name OR role ID.
 * * actionLogger logr: Used for logging.
 *
 * DESCRIPTION
 * 1. First, compare the role's `Description` and `Attributes`. If there is a difference, issue an UPDATE ROLE request.
 * 2. If the `Composite` attribute is `true` for the actual OR desired state, then also resolve differences in composites list.
 *   a. Fetch the current list of composites for the actual role from the Keycloak API, and compare it to the desired list from the CR.
 *   b. If necessary, add new composites (in single Keycloak API request)
 *   c. If necessary, remove existing composites (in single Keycloak API request)
 *
 * "Fails fast" and prints error if any Keycloak API request fails.
**/
func (i *ClusterActionRunner) compareAndUpdateRealmRole(realmName string, dRole *v1alpha1.RoleRepresentation, aRole *v1alpha1.RoleRepresentation, allActualRolesMap map[string]*v1alpha1.RoleRepresentation, actionLogger logr.Logger) error {
	roleLogger := actionLogger.WithValues("Realm.Role", dRole.Name)

	// Step 1
	if !genericEqualsRealmRoles(dRole, aRole) {
		roleLogger.Info(fmt.Sprintf("[REALM ROLE CHANGE] Update generic values of realm role %v.", aRole.Name))
		err := i.keycloakClient.UpdateRealmRole(dRole, realmName, aRole.ID)
		if err != nil {
			roleJSON, jsonerr := json.Marshal(*dRole)
			if jsonerr != nil {
				roleLogger.Info(fmt.Sprintf("[REALM ROLE CHANGE - ERROR] Unable to update realm role %v, and unable to marshal JSON.", aRole.Name))
				return err
			}
			roleLogger.Info(fmt.Sprintf("[REALM ROLE CHANGE - ERROR] Unable to update realm role %s", roleJSON))
			return err
		}
	}

	// Step 2 - First check if needed. Logic: https://go.dev/play/p/gDvSJ-lzqws
	if (aRole.Composite == nil || !*aRole.Composite) && (dRole.Composite == nil || !*dRole.Composite) {
		return nil
	}

	// Step 2A
	aRoleComposites, err := i.keycloakClient.ListRealmRoleComposites(realmName, aRole.ID)
	if err != nil {
		return err
	}

	aRoleCompositeNames := []string{}
	for _, r := range aRoleComposites {
		aRoleCompositeNames = append(aRoleCompositeNames, r.Name)
	}
	dRoleCompositeNames := safelyGetCompositeNames(dRole)

	compositesToRemove := difference(aRoleCompositeNames, dRoleCompositeNames)
	compositesToAdd := difference(dRoleCompositeNames, aRoleCompositeNames)

	// Step 2B - Add realm role composites
	if len(compositesToAdd) > 0 {
		addList := []v1alpha1.RoleRepresentation{}
		for _, name := range compositesToAdd {
			addList = append(addList, *allActualRolesMap[name])
		}
		roleLogger.Info(fmt.Sprintf("[REALM ROLE COMPOSITE CHANGE] Adding new composite roles %v.", compositesToAdd))
		err = i.keycloakClient.AddRealmRoleComposites(realmName, aRole.ID, &addList)
		if err != nil {
			rolesJSON, jsonerr := json.Marshal(addList)
			if jsonerr != nil {
				roleLogger.Info(fmt.Sprintf("[REALM ROLE COMPOSITE CHANGE - ERROR] Unable to add new composite roles %v, and unable to marshal JSON.", compositesToAdd))
				return err
			}
			roleLogger.Info(fmt.Sprintf("[REALM ROLE COMPOSITE CHANGE - ERROR] Unable to add new composite roles %v", rolesJSON))
			return err
		}
	}

	// Step 2C - Remove realm role composites
	if len(compositesToRemove) > 0 {
		removeList := []v1alpha1.RoleRepresentation{}
		for _, name := range compositesToRemove {
			removeList = append(removeList, *allActualRolesMap[name])
		}
		roleLogger.Info(fmt.Sprintf("[REALM ROLE COMPOSITE CHANGE] Removing existing composite roles %v.", compositesToRemove))
		err = i.keycloakClient.DeleteRealmRoleComposites(realmName, aRole.ID, &removeList)
		if err != nil {
			drolesJSON, jsonerr := json.Marshal(removeList)
			if jsonerr != nil {
				roleLogger.Info(fmt.Sprintf("[REALM ROLE COMPOSITE CHANGE - ERROR] Unable to remove existing composite roles %v, and unable to marshal JSON.", compositesToRemove))
				return err
			}
			roleLogger.Info(fmt.Sprintf("[REALM ROLE COMPOSITE CHANGE - ERROR] Unable to remove existing composite roles %v", drolesJSON))
			return err
		}
	}
	return nil
}

/**
 * Business logic to compare and issue limited updates for Authorization Flows in the realm. This logic will compare the "desired state" of authentication flows parsed from the
 * KeycloakRealm CR against the "actual state" queried from the KC admin api. This logic compares all custom top-level flows, comparing each execution step and recursively
 * comparing sub-flows.
 *
 * Concepts of auth flows and how they are nested:
 *  * An authentication flow contains a unique name (alias) and an ordered list of execution steps.
 *  * An execution step is represented in the KC admin UI by a single table row. It contains a requirement level, and is either type "authenticator" or "sub-flow" based on the boolean value `authenticatorFlow`.
 *    * If an execution step is an authenticator, it contains a reference to a provider java class in KC (by name), and optional configuration for using the provider class.
 *    * If an execution step is a sub-flow, it contains a name, description, and a reference to an authentication flow object (by flowID, not alias)
 *  * An authentication flow has a boolean field `topLevel` which determines it's type.
 *    * IF topLevel == false, the flow is a sub-flow and is referenced by some execution step.
 *    * IF topLevel == true, the flow can be set as the primary flow for one of the core authentication paths (login, registration, password reset, etc)
 *
 *
 * Only limited kinds Authentication Flow updates are currently supported. Unsupported changes can be because: some fields/updates are not allowed in the Keycloak API, some changes we do not
 * want to occur automatically because they could be dangerous, and some items are less of a priority and have not been implemented yet due to time/complexity (marked with TODO below).
 *
 * Supported Changes:
 *   * Update requirenment level of an execution step (i.e. anser-secret-questions REQUIRED -> DISABLED in reset password flow.)
 *   * When execution step is type sub-flow:
 *     * Update to the sub-flow's name (alias)
 *   * Deletion of an execution step (authenticator type or sub-flow type)
 *   * When execution step is type authenticator (and NOT a sub-flow):
 *     * Update the `ProviderID`, which is the reference to the java class for execution.
 *     * Update the text Description of the execution step.
 *
 *
 * Unsupported:
 *   * Any management of the "built-in" flows.
 *   * Deletion of exisiting top-level flow (This is for safety. The operator will continuously log that the auth flow should be manually removed.)
 *   * Creation of new top-level flow (will be logged by operator, but not created in KC.) TODO
 *   * Changing an execution's type from "authenticator type" to "sub-flow type" or vice versa (updates to authenticatorFlow boolean value). This is disallowed by the Keycloak API, must delete and re-create.
 *   * Re-ordering execution steps based on updated Priority. TODO
 *   * Creation of new execution steps in a flow. TODO
 *   * When execution step is type sub-flow:
 *     * Changing the description. (Keycloak API does ignores this change, seems to be a KC bug)
 *   * When execution step is type authenticator (and NOT a sub-flow):
 *     * Changing the provider class referenced by the authenticator (not supported by KC API, requires delete + recreate)
 *
**/
func (i *ClusterActionRunner) configureAuthenticationFlows(obj *v1alpha1.KeycloakRealm) error {
	actionLogger := log.WithValues("Request.Namespace", obj.Namespace, "Request.Name", obj.Name)

	realmName := obj.Spec.Realm.Realm

	// The CR definition defines ALL flows and sub-flows in a big list.
	allDesiredFlows := obj.Spec.Realm.AuthenticationFlows

	// The keycloak API returns only the TOP LEVEL flows (not sub-flows).
	topLevelActualFlows, err := i.keycloakClient.ListAuthenticationFlows(realmName)
	if err != nil {
		return err
	}

	if len(topLevelActualFlows) == 0 {
		actionLogger.Info("Error: No existing authentication flows found")
		return nil
	}

	// Gather names (use aliases. top level, custom flows only)
	actualFlowNames := []string{}
	desiredFlowNames := []string{}
	for _, dflow := range allDesiredFlows {
		if dflow.TopLevel && !dflow.BuiltIn {
			desiredFlowNames = append(desiredFlowNames, dflow.Alias)
		}
	}
	for _, aflow := range topLevelActualFlows {
		if aflow.TopLevel && !aflow.BuiltIn {
			actualFlowNames = append(actualFlowNames, aflow.Alias)
		}
	}

	// Categorize Top Level Comparisons
	flowsToRemove := difference(actualFlowNames, desiredFlowNames)
	flowsToAdd := difference(desiredFlowNames, actualFlowNames)
	flowsToCompare := difference(union(actualFlowNames, desiredFlowNames), append(flowsToAdd, flowsToRemove...))
	actionLogger.Info(fmt.Sprintf("[FLOW] Removing: %v, Adding: %v, Comparing: %v", flowsToRemove, flowsToAdd, flowsToCompare))

	// Delete/Create currently unsupported
	for _, name := range flowsToRemove {
		actionLogger.Info(fmt.Sprintf("WARNING: Deleting top level authentication flow %s is not supported. Safe to manually delete.", name))
	}
	for _, name := range flowsToAdd {
		actionLogger.Info(fmt.Sprintf("ERROR: Creating top level authentication flow %s is not supported. Implementation Needed!", name))
	}

	// Do updates
	for _, name := range flowsToCompare {
		actionLogger.Info(fmt.Sprintf("Top-level comparison of %v flow.", name))
		allActualExecutionInfos, err := i.keycloakClient.ListAuthenticationExecutionsForFlow(name, realmName)
		if err != nil {
			return err
		}

		aflow := getFlowInListOfPointers(name, topLevelActualFlows)
		dflow := getFlowInList(name, allDesiredFlows)
		recurseErr := i.recursivelyReconcileAuthFlow(realmName, name, dflow, aflow, allDesiredFlows, allActualExecutionInfos, actionLogger)
		if recurseErr != nil {
			return recurseErr
		}
	}

	return nil
}

/**
 * RECURSIVELY RECONCILE AUTH FLOW
 *
 * ARGS
 * * realmName string, used by keycloakClient for http requests
 * * dflowQualifiedName string, used for logging only
 * * dflow KeycloakAPIAuthenticationFlow: The desired state for comparison, parsed from the CR definition
 * * aflow KeycloakAPIAuthenticationFlow: The actual state for comparison, queried from the Keycloak API
 * * allDesiredFlows []KeycloakAPIAuthenticationFlow: A full list of flows defined in the CR (top level and sub-flows), and used to lookup the next `dflow`, when using the recursion
 * * allActualExecutionInfos []AuthenticationExecutionInfo: A full list of execution steps for the current top level flow (not current `aflow`).
 *
 * When executing the recursive call, the args `dflow`, `aflow`, and `dflowQualifiedName` are updated, to the next level of sub-flow to be compared (all other args do not change).
 *
 * DESCRIPTION
 * Performs a deep comparison between the "current authentication flow" state, represented as `aflow`, and the "desired authentication flow" state, represented as `dflow`.
 * 1. First, compares flow attributes `ProviderID` and `Description`. Other attributes `TopLevel` and `BuiltIn` are immutable and so not compared.
 * 2. Next, do a list comparison of the two flow's `AuthenticationExecution` lists to identify added/removed/comparison execution steps.
 * 3. Create and Delete execution steps identified as added or removed in the previous step. Currently not supported, a message is logged instead.
 * 4. Iterate over the execution steps that exist in both flows, comparing each one.
 *   a. Compare the "Required" attribute, the only attribute that can be directly modified here.
 *   b. If the `AuthenticationExecution` is a sub-flow, look-up the next flow for actual and desired, then recursively call flow comparison.
 * 5. Compare the order of the execution steps, based on their priority, and calculate "up"/"down" HTTP requests required to get the desired order. //TODO
 *
 *
 * "Fails fast" and and stops comparing as soon as anything fails. Returning an error causes the reconciliation to be requeued again in 1 minutes in case of temporary failures.
**/
func (i *ClusterActionRunner) recursivelyReconcileAuthFlow(realmName string, dflowQualifiedName string, dflow *v1alpha1.KeycloakAPIAuthenticationFlow, aflow *v1alpha1.KeycloakAPIAuthenticationFlow, allDesiredFlows []v1alpha1.KeycloakAPIAuthenticationFlow, allActualExecutionInfos []*v1alpha1.AuthenticationExecutionInfo, actionLogger logr.Logger) error { //nolint
	topLevelFlowName := strings.Split(dflowQualifiedName, " -> ")[0]
	flowLogger := actionLogger.WithValues("Realm.TopLevelFlow", topLevelFlowName, "Realm.Flow.SubFlow", dflowQualifiedName)

	// Step 1
	if dflow.Description != aflow.Description || dflow.ProviderID != aflow.ProviderID {
		flowLogger.Info(fmt.Sprintf("[FLOW CHANGE] Different Description or ProviderID. Update by ID: %v", aflow.ID))
		dflow.ID = aflow.ID
		err := i.keycloakClient.UpdateAuthenticationFlow(realmName, dflow)
		if err != nil {
			flowLogger.Info(fmt.Sprintf("[FLOW CHANGE - ERROR] Unable to update authentication flow. Update by ID: %v", aflow.ID))
			return err
		}
	}

	// Step 2
	desiredExecutionStepNames := []string{}
	actualExecutionStepNames := []string{}
	for _, dstep := range dflow.AuthenticationExecutions {
		if dstep.AuthenticatorFlow {
			desiredExecutionStepNames = append(desiredExecutionStepNames, dstep.FlowAlias)
		} else {
			desiredExecutionStepNames = append(desiredExecutionStepNames, dstep.Authenticator)
		}
	}
	for _, astep := range aflow.AuthenticationExecutions {
		if astep.AuthenticatorFlow {
			actualExecutionStepNames = append(actualExecutionStepNames, astep.FlowAlias)
		} else {
			actualExecutionStepNames = append(actualExecutionStepNames, astep.Authenticator)
		}
	}

	// Categorize Execution Step Comparisons
	stepsToRemove := difference(actualExecutionStepNames, desiredExecutionStepNames)
	stepsToAdd := difference(desiredExecutionStepNames, actualExecutionStepNames)
	stepsToCompare := difference(union(actualExecutionStepNames, desiredExecutionStepNames), append(stepsToAdd, stepsToRemove...))

	// Step 3
	for _, executionName := range stepsToRemove {
		payloadID := getExecutionInfoInList(getExecutionInList(executionName, aflow.AuthenticationExecutions), allActualExecutionInfos).ID
		flowLogger.Info(fmt.Sprintf("[FLOW CHANGE] Delete Execution Step. Delete by ID: %v", payloadID))
		err := i.keycloakClient.DeleteAuthenticationExecutionForFlow(realmName, payloadID)
		if err != nil {
			flowLogger.Info(fmt.Sprintf("[FLOW CHANGE - ERROR] Unable to remove execution step from authentication flow. Delete by ID: %v", payloadID))
			return err
		}
	}
	for _, executionName := range stepsToAdd {
		flowLogger.Info(fmt.Sprintf("[FLOW CHANGE - WARNING]: Creating new execution step %v from %v is not supported.", executionName, dflowQualifiedName))
	}

	// Step 4
	for _, executionName := range stepsToCompare {
		dExecution := getExecutionInList(executionName, dflow.AuthenticationExecutions)
		aExecution := getExecutionInList(executionName, aflow.AuthenticationExecutions)

		// Step 4A - Test Requirement level
		if dExecution.Requirement != aExecution.Requirement {
			flowLogger.Info(fmt.Sprintf("[FLOW CHANGE] Set Requiernment Level to %v for AuthenticationExecution step %v", dExecution.Requirement, executionName))
			payload := v1alpha1.AuthenticationExecutionInfo{
				ID:          getExecutionInfoInList(aExecution, allActualExecutionInfos).ID,
				Requirement: dExecution.Requirement,
			}

			err := i.keycloakClient.UpdateAuthenticationExecutionForFlow(dflow.Alias, realmName, &payload)
			if err != nil {
				flowLogger.Info(fmt.Sprintf("[FLOW CHANGE - ERROR] Unable to update requirement level. Update by ID: %v", payload.ID))
				return err
			}
		}

		// Step 4B - Retrieve and then recursively compare sub-flows.
		if dExecution.AuthenticatorFlow == true { //nolint
			subFlowAlias := dExecution.FlowAlias

			// dSubFlow just comes from the immutable list of all sub-flows defined in the CR
			dSubFlow := getFlowInList(subFlowAlias, allDesiredFlows)
			if dSubFlow == nil {
				return errors.Errorf("Referenced sub-flow [%v] is not defined in KeycloakRealm custom resource. Please check for CR definition.", subFlowAlias)
			}

			// For aSubFlow you need to find the ExecutionInfo first from the immutable list of all the actual execution steps.
			// Then, retrieve FlowID from the ExecutionInfo object and query that sub-flow with Keycloak api call.
			aExecutionInfo := getExecutionInfoInList(aExecution, allActualExecutionInfos)
			if aExecutionInfo == nil {
				return errors.Errorf("Internal Error. Unable to find AuthenticationExecutionInfo obj with DisplayName %v in results from Keycloak API.", subFlowAlias)
			}

			aSubFlow, err := i.keycloakClient.GetAuthenticationFlowByID(aExecutionInfo.FlowID, realmName)
			if err != nil {
				flowLogger.Error(err, "Keycloak HTTP Error. Error trying to retrieve sub-flow.")
				return err
			}
			// 404, which should not happen here, since we've already validated this sub-flow exists.
			if aSubFlow == nil {
				return errors.Errorf("Unable to GET sub-flow with ID %v", aExecutionInfo.FlowID)
			}

			recurseErr := i.recursivelyReconcileAuthFlow(realmName, (dflowQualifiedName + " -> " + subFlowAlias), dSubFlow, aSubFlow, allDesiredFlows, allActualExecutionInfos, actionLogger) //recurse
			if recurseErr != nil {
				return recurseErr
			}
		}
	}
	return nil
}

/**
 * UTIL-LIKE HELPER FUNCTIONS
**/

// Compare a desired vs actual RoleRepresentation for differences in Name, Description or Attributes
func genericEqualsRealmRoles(drole *v1alpha1.RoleRepresentation, arole *v1alpha1.RoleRepresentation) bool {
	return arole.Description == drole.Description && arole.Name == drole.Name && reflect.DeepEqual(arole.Attributes, drole.Attributes)
}

// If any nested portion is nil, an empty list is returned.
func safelyGetCompositeNames(drole *v1alpha1.RoleRepresentation) []string {
	names := []string{}
	if drole.Composites != nil {
		if drole.Composites.Realm != nil {
			names = drole.Composites.Realm
		}
	}
	return names
}

// Create Map that maps alias to the KeycloakAPIRequiredAction, and return a list of the required action aliases.
func prepareActualRealmRequiredActions(actualRealmRequiredActions []*v1alpha1.KeycloakAPIRequiredAction) ([]string, map[string]*v1alpha1.KeycloakAPIRequiredAction) {
	actualRequiredActionMap := make(map[string]*v1alpha1.KeycloakAPIRequiredAction)
	actualRequiredActionAliases := []string{}
	for _, aRequiredAction := range actualRealmRequiredActions {
		actualRequiredActionMap[aRequiredAction.Alias] = aRequiredAction
    actualRequiredActionAliases = append(actualRequiredActionAliases, aRequiredAction.Alias)
	}
	return actualRequiredActionAliases, actualRequiredActionMap
}

// Return a list of the desired realm role actions aliases.
func prepareDesiredRealmRequiredActions(obj *v1alpha1.KeycloakRealm) ([]string, map[string]*v1alpha1.KeycloakAPIRequiredAction) {
	desiredRequiredActionMap := make(map[string]*v1alpha1.KeycloakAPIRequiredAction)
	desiredRequiredActionAliases := []string{}

	// Safety check to avoid panic
	if obj.Spec.Realm.RequiredActions == nil {
		return desiredRequiredActionAliases, desiredRequiredActionMap // return empty structures
	}

	desiredRealmRequiredActions := obj.Spec.Realm.RequiredActions
	for _, dRequiredAction := range desiredRealmRequiredActions {
		dRequiredActionCopy := dRequiredAction // IMPORTANT! See: https://stackoverflow.com/a/48826629
		desiredRequiredActionMap[dRequiredActionCopy.Alias] = &dRequiredActionCopy
    desiredRequiredActionAliases = append(desiredRequiredActionAliases, dRequiredActionCopy.Alias)
	}
	return desiredRequiredActionAliases, desiredRequiredActionMap
}

// Create Map that maps name OR id to the KeycloakClientScope, and return a list of the client scope names.
func prepareActualRealmClientScopes(actualRealmClientScopes []v1alpha1.KeycloakClientScope) ([]string, map[string]v1alpha1.KeycloakClientScope) {
	actualClientScopeMap := make(map[string]v1alpha1.KeycloakClientScope)
	actualClientScopeNames := []string{}
	for _, aClientScope := range actualRealmClientScopes {
		actualClientScopeMap[aClientScope.Name] = aClientScope
		actualClientScopeMap[aClientScope.ID] = aClientScope
    actualClientScopeNames = append(actualClientScopeNames, aClientScope.Name)
	}
	return actualClientScopeNames, actualClientScopeMap
}

// Create Map from client scope name to client scope, and return a list of the client scope names.
func prepareDesiredRealmClientScopes(obj *v1alpha1.KeycloakRealm) ([]string, map[string]*v1alpha1.KeycloakClientScope) {
	desiredClientScopeMap := make(map[string]*v1alpha1.KeycloakClientScope)
	desiredClientScopeNames := []string{}

	// Safety check to avoid panic
	if obj.Spec.Realm.ClientScopes == nil {
		return desiredClientScopeNames, desiredClientScopeMap // return empty structures
	}

	desiredRealmClientScopes := obj.Spec.Realm.ClientScopes
	for _, dClientScope := range desiredRealmClientScopes {
		dClientScopeCopy := dClientScope // IMPORTANT! See: https://stackoverflow.com/a/48826629
		desiredClientScopeMap[dClientScopeCopy.Name] = &dClientScopeCopy
    desiredClientScopeNames = append(desiredClientScopeNames, dClientScopeCopy.Name)
	}
	return desiredClientScopeNames, desiredClientScopeMap
}

// Create Map that maps name OR id to the RoleRepresentation, and return a list of the role names.
func prepareActualRealmRoles(actualRealmRoles []*v1alpha1.RoleRepresentation, ignoredRolesList []string) ([]string, map[string]*v1alpha1.RoleRepresentation) {
	actualRoleMap := make(map[string]*v1alpha1.RoleRepresentation)
	actualRoleNames := []string{}
	for _, arole := range actualRealmRoles {
		actualRoleMap[arole.Name] = arole
		actualRoleMap[arole.ID] = arole
		if !contains(ignoredRolesList, arole.Name) {
			actualRoleNames = append(actualRoleNames, arole.Name)
		}
	}
	return actualRoleNames, actualRoleMap
}

// Create Map from role name to role, and return a list of the role names.
func prepareDesiredRealmRoles(obj *v1alpha1.KeycloakRealm, ignoredRolesList []string) ([]string, map[string]*v1alpha1.RoleRepresentation) {
	desiredRoleMap := make(map[string]*v1alpha1.RoleRepresentation)
	desiredRoleNames := []string{}

	// Safety check to avoid panic
	if obj.Spec.Realm.Roles == nil || obj.Spec.Realm.Roles.Realm == nil {
		return desiredRoleNames, desiredRoleMap // return empty structures
	}

	desiredRealmRoles := obj.Spec.Realm.Roles.Realm
	for _, drole := range desiredRealmRoles {
		droleCopy := drole // IMPORTANT! See: https://stackoverflow.com/a/48826629
		desiredRoleMap[droleCopy.Name] = &droleCopy
		if !contains(ignoredRolesList, droleCopy.Name) {
			desiredRoleNames = append(desiredRoleNames, droleCopy.Name)
		}
	}
	return desiredRoleNames, desiredRoleMap
}

// Look up auth flow in a list by it's alias
func getFlowInList(alias string, list []v1alpha1.KeycloakAPIAuthenticationFlow) *v1alpha1.KeycloakAPIAuthenticationFlow {
	for _, val := range list {
		if val.Alias == alias {
			return &val
		}
	}
	return nil
}

// Couldn't find a way around this duplication
func getFlowInListOfPointers(alias string, list []*v1alpha1.KeycloakAPIAuthenticationFlow) *v1alpha1.KeycloakAPIAuthenticationFlow {
	for _, val := range list {
		if val.Alias == alias {
			return val
		}
	}
	return nil
}

func getExecutionInList(alias string, list []v1alpha1.KeycloakAPIAuthenticationExecution) *v1alpha1.KeycloakAPIAuthenticationExecution {
	for _, val := range list {
		if val.Authenticator == alias || val.FlowAlias == alias {
			return &val
		}
	}
	return nil
}

func getExecutionInfoInList(execution *v1alpha1.KeycloakAPIAuthenticationExecution, list []*v1alpha1.AuthenticationExecutionInfo) *v1alpha1.AuthenticationExecutionInfo {
	for _, val := range list {
		if execution.AuthenticatorFlow && val.DisplayName == execution.FlowAlias {
			return val
		}
		if !execution.AuthenticatorFlow && val.ProviderID == execution.Authenticator {
			return val
		}
	}
	return nil
}

// difference returns the elements in `a` that aren't in `b`.
func difference(a, b []string) []string {
	mb := make(map[string]struct{}, len(b))
	for _, x := range b {
		mb[x] = struct{}{}
	}
	var diff []string
	for _, x := range a {
		if _, found := mb[x]; !found {
			diff = append(diff, x)
		}
	}
	return diff
}

// contains returns true iff `str` is one of the values in `s`
func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}
	return false
}

// union returns the all elements in `a` and all the elments in `b` (no duplicates)
func union(a, b []string) []string {
	check := make(map[string]int)
	d := append(a, b...)
	union := make([]string, 0)
	for _, val := range d {
		check[val] = 1
	}

	for letter := range check {
		union = append(union, letter)
	}

	return union
}

/*
* ACTION STRUCTURES
 */

// An action to create generic kubernetes resources
// (resources that don't require special treatment)
type GenericCreateAction struct {
	Ref runtime.Object
	Msg string
}

// An action to update generic kubernetes resources
// (resources that don't require special treatment)
type GenericUpdateAction struct {
	Ref runtime.Object
	Msg string
}

// An action to delete generic kubernetes resources
// (resources that don't require special treatment)
type GenericDeleteAction struct {
	Ref runtime.Object
	Msg string
}

type CreateRealmAction struct {
	Ref *v1alpha1.KeycloakRealm
	Msg string
}

type UpdateRealmAction struct {
	Ref *v1alpha1.KeycloakRealm
	Msg string
}

type CreateClientAction struct {
	Ref   *v1alpha1.KeycloakClient
	Msg   string
	Realm string
}

type UpdateClientAction struct {
	Ref   *v1alpha1.KeycloakClient
	Msg   string
	Realm string
}

type DeleteRealmAction struct {
	Ref *v1alpha1.KeycloakRealm
	Msg string
}

type DeleteClientAction struct {
	Ref   *v1alpha1.KeycloakClient
	Realm string
	Msg   string
}

type CreateClientRoleAction struct {
	Role  *v1alpha1.RoleRepresentation
	Ref   *v1alpha1.KeycloakClient
	Msg   string
	Realm string
}

type UpdateClientRoleAction struct {
	Role    *v1alpha1.RoleRepresentation
	OldRole *v1alpha1.RoleRepresentation
	Ref     *v1alpha1.KeycloakClient
	Msg     string
	Realm   string
}

type DeleteClientRoleAction struct {
	Role  *v1alpha1.RoleRepresentation
	Ref   *v1alpha1.KeycloakClient
	Msg   string
	Realm string
}

type AddDefaultRolesAction struct {
	Roles              *[]v1alpha1.RoleRepresentation
	DefaultRealmRoleID string
	Ref                *v1alpha1.KeycloakClient
	Msg                string
	Realm              string
}

type DeleteDefaultRolesAction struct {
	Roles              *[]v1alpha1.RoleRepresentation
	DefaultRealmRoleID string
	Ref                *v1alpha1.KeycloakClient
	Msg                string
	Realm              string
}

type CreateClientRealmScopeMappingsAction struct {
	Mappings *[]v1alpha1.RoleRepresentation
	Ref      *v1alpha1.KeycloakClient
	Msg      string
	Realm    string
}

type DeleteClientRealmScopeMappingsAction struct {
	Mappings *[]v1alpha1.RoleRepresentation
	Ref      *v1alpha1.KeycloakClient
	Msg      string
	Realm    string
}

type CreateClientClientScopeMappingsAction struct {
	Mappings *v1alpha1.ClientMappingsRepresentation
	Ref      *v1alpha1.KeycloakClient
	Msg      string
	Realm    string
}

type DeleteClientClientScopeMappingsAction struct {
	Mappings *v1alpha1.ClientMappingsRepresentation
	Ref      *v1alpha1.KeycloakClient
	Msg      string
	Realm    string
}

type UpdateClientDefaultClientScopeAction struct {
	ClientScope *v1alpha1.KeycloakClientScope
	Ref         *v1alpha1.KeycloakClient
	Msg         string
	Realm       string
}

type DeleteClientDefaultClientScopeAction struct {
	ClientScope *v1alpha1.KeycloakClientScope
	Ref         *v1alpha1.KeycloakClient
	Msg         string
	Realm       string
}

type UpdateClientOptionalClientScopeAction struct {
	ClientScope *v1alpha1.KeycloakClientScope
	Ref         *v1alpha1.KeycloakClient
	Msg         string
	Realm       string
}

type DeleteClientOptionalClientScopeAction struct {
	ClientScope *v1alpha1.KeycloakClientScope
	Ref         *v1alpha1.KeycloakClient
	Msg         string
	Realm       string
}

type UpdateRealmRolesAction struct {
	Ref *v1alpha1.KeycloakRealm
	Msg string
}

type UpdateRealmClientScopesAction struct {
	Ref *v1alpha1.KeycloakRealm
	Msg string
}

type UpdateRealmRequiredActionsAction struct {
	Ref *v1alpha1.KeycloakRealm
	Msg string
}

type UpdateAuthenticationFlowsAction struct {
	Ref *v1alpha1.KeycloakRealm
	Msg string
}

type ConfigureRealmAction struct {
	Ref *v1alpha1.KeycloakRealm
	Msg string
}

type PingAction struct {
	Msg string
}

type CreateUserAction struct {
	Ref   *v1alpha1.KeycloakUser
	Realm string
	Msg   string
}

type UpdateUserAction struct {
	Ref   *v1alpha1.KeycloakUser
	Realm string
	Msg   string
}

type DeleteUserAction struct {
	ID    string
	Realm string
	Msg   string
}

type AssignRealmRoleAction struct {
	UserID string
	Ref    *v1alpha1.KeycloakUserRole
	Realm  string
	Msg    string
}

type RemoveRealmRoleAction struct {
	UserID string
	Ref    *v1alpha1.KeycloakUserRole
	Realm  string
	Msg    string
}

type AssignClientRoleAction struct {
	UserID   string
	ClientID string
	Ref      *v1alpha1.KeycloakUserRole
	Realm    string
	Msg      string
}

type RemoveClientRoleAction struct {
	UserID   string
	ClientID string
	Ref      *v1alpha1.KeycloakUserRole
	Realm    string
	Msg      string
}

func (i GenericCreateAction) Run(runner ActionRunner) (string, error) {
	return i.Msg, runner.Create(i.Ref)
}

func (i GenericUpdateAction) Run(runner ActionRunner) (string, error) {
	return i.Msg, runner.Update(i.Ref)
}

func (i GenericDeleteAction) Run(runner ActionRunner) (string, error) {
	return i.Msg, runner.Delete(i.Ref)
}

func (i CreateRealmAction) Run(runner ActionRunner) (string, error) {
	return i.Msg, runner.CreateRealm(i.Ref)
}

func (i UpdateRealmAction) Run(runner ActionRunner) (string, error) {
	return i.Msg, runner.UpdateRealm(i.Ref)
}

func (i CreateClientAction) Run(runner ActionRunner) (string, error) {
	return i.Msg, runner.CreateClient(i.Ref, i.Realm)
}

func (i UpdateClientAction) Run(runner ActionRunner) (string, error) {
	return i.Msg, runner.UpdateClient(i.Ref, i.Realm)
}

func (i CreateClientRoleAction) Run(runner ActionRunner) (string, error) {
	return i.Msg, runner.CreateClientRole(i.Ref, i.Role, i.Realm)
}

func (i UpdateClientRoleAction) Run(runner ActionRunner) (string, error) {
	return i.Msg, runner.UpdateClientRole(i.Ref, i.Role, i.OldRole, i.Realm)
}

func (i DeleteClientRoleAction) Run(runner ActionRunner) (string, error) {
	return i.Msg, runner.DeleteClientRole(i.Ref, i.Role.Name, i.Realm)
}

func (i AddDefaultRolesAction) Run(runner ActionRunner) (string, error) {
	return i.Msg, runner.AddDefaultRoles(i.Roles, i.DefaultRealmRoleID, i.Realm)
}

func (i DeleteDefaultRolesAction) Run(runner ActionRunner) (string, error) {
	return i.Msg, runner.DeleteDefaultRoles(i.Roles, i.DefaultRealmRoleID, i.Realm)
}

func (i CreateClientRealmScopeMappingsAction) Run(runner ActionRunner) (string, error) {
	return i.Msg, runner.CreateClientRealmScopeMappings(i.Ref, i.Mappings, i.Realm)
}

func (i DeleteClientRealmScopeMappingsAction) Run(runner ActionRunner) (string, error) {
	return i.Msg, runner.DeleteClientRealmScopeMappings(i.Ref, i.Mappings, i.Realm)
}

func (i CreateClientClientScopeMappingsAction) Run(runner ActionRunner) (string, error) {
	return i.Msg, runner.CreateClientClientScopeMappings(i.Ref, i.Mappings, i.Realm)
}

func (i DeleteClientClientScopeMappingsAction) Run(runner ActionRunner) (string, error) {
	return i.Msg, runner.DeleteClientClientScopeMappings(i.Ref, i.Mappings, i.Realm)
}

func (i UpdateClientDefaultClientScopeAction) Run(runner ActionRunner) (string, error) {
	return i.Msg, runner.UpdateClientDefaultClientScope(i.Ref, i.ClientScope, i.Realm)
}

func (i DeleteClientDefaultClientScopeAction) Run(runner ActionRunner) (string, error) {
	return i.Msg, runner.DeleteClientDefaultClientScope(i.Ref, i.ClientScope, i.Realm)
}

func (i UpdateClientOptionalClientScopeAction) Run(runner ActionRunner) (string, error) {
	return i.Msg, runner.UpdateClientOptionalClientScope(i.Ref, i.ClientScope, i.Realm)
}

func (i DeleteClientOptionalClientScopeAction) Run(runner ActionRunner) (string, error) {
	return i.Msg, runner.DeleteClientOptionalClientScope(i.Ref, i.ClientScope, i.Realm)
}

func (i DeleteRealmAction) Run(runner ActionRunner) (string, error) {
	return i.Msg, runner.DeleteRealm(i.Ref)
}

func (i DeleteClientAction) Run(runner ActionRunner) (string, error) {
	return i.Msg, runner.DeleteClient(i.Ref, i.Realm)
}

func (i PingAction) Run(runner ActionRunner) (string, error) {
	return i.Msg, runner.Ping()
}

func (i ConfigureRealmAction) Run(runner ActionRunner) (string, error) {
	return i.Msg, runner.ApplyOverrides(i.Ref)
}

func (i UpdateRealmRolesAction) Run(runner ActionRunner) (string, error) {
	return i.Msg, runner.UpdateRealmRoles(i.Ref)
}

func (i UpdateRealmClientScopesAction) Run(runner ActionRunner) (string, error) {
	return i.Msg, runner.UpdateRealmClientScopes(i.Ref)
}

func (i UpdateRealmRequiredActionsAction) Run(runner ActionRunner) (string, error) {
	return i.Msg, runner.UpdateRealmRequiredActions(i.Ref)
}

func (i UpdateAuthenticationFlowsAction) Run(runner ActionRunner) (string, error) {
	return i.Msg, runner.UpdateAuthenticationFlows(i.Ref)
}

func (i CreateUserAction) Run(runner ActionRunner) (string, error) {
	return i.Msg, runner.CreateUser(i.Ref, i.Realm)
}

func (i UpdateUserAction) Run(runner ActionRunner) (string, error) {
	return i.Msg, runner.UpdateUser(i.Ref, i.Realm)
}

func (i DeleteUserAction) Run(runner ActionRunner) (string, error) {
	return i.Msg, runner.DeleteUser(i.ID, i.Realm)
}

func (i AssignRealmRoleAction) Run(runner ActionRunner) (string, error) {
	return i.Msg, runner.AssignRealmRole(i.Ref, i.UserID, i.Realm)
}

func (i RemoveRealmRoleAction) Run(runner ActionRunner) (string, error) {
	return i.Msg, runner.RemoveRealmRole(i.Ref, i.UserID, i.Realm)
}

func (i AssignClientRoleAction) Run(runner ActionRunner) (string, error) {
	return i.Msg, runner.AssignClientRole(i.Ref, i.ClientID, i.UserID, i.Realm)
}

func (i RemoveClientRoleAction) Run(runner ActionRunner) (string, error) {
	return i.Msg, runner.RemoveClientRole(i.Ref, i.ClientID, i.UserID, i.Realm)
}
