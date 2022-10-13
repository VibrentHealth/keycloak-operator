package common

import (
	"context"
	"fmt"
	"sort"
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

func (i *ClusterActionRunner) UpdateAuthenticationFlows(obj *v1alpha1.KeycloakRealm) error {
	if i.keycloakClient == nil {
		return errors.Errorf("cannot perform authentication flow configure when client is nil")
	}
	
	return i.configureAuthenticationFlows(obj)
}

/*
* PRIVATE BUSINESS FUNCTIONS
*/



func (i *ClusterActionRunner) configureAuthenticationFlows(obj *v1alpha1.KeycloakRealm) error {
	actionLogger := log.WithValues("Request.Namespace", obj.Namespace, "Request.Name", obj.Name)

	realmName := obj.Spec.Realm.Realm
	
	// The CR definition defines ALL flows and subflows in a big list.
	allDesiredFlows := obj.Spec.Realm.AuthenticationFlows
	
	// The keycloak API returns only the TOP LEVEL flows.
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
		if dflow.TopLevel == true && dflow.BuiltIn != true {
			desiredFlowNames = append(desiredFlowNames, dflow.Alias)
		}
	}
	for _, aflow := range topLevelActualFlows {
		if aflow.TopLevel == true && aflow.BuiltIn != true {
			actualFlowNames = append(actualFlowNames, aflow.Alias)
		}
	}
	
	// Top Level Comparison
	flowsToRemove := difference(actualFlowNames, desiredFlowNames)
	flowsToAdd := difference(desiredFlowNames, actualFlowNames)
	flowsToCompare := difference(union(actualFlowNames, desiredFlowNames), append(flowsToAdd, flowsToRemove...))
	
	// Do updates
	for _, name := range flowsToRemove {
		actionLogger.Info(fmt.Sprintf("Deleting Authentication Flow %s is not supported", name))
//		actionLogger.Info(fmt.Sprintf("Removing Authentication Flow: %s", name))
//		err := i.keycloakClient.DeleteAuthenticationFlow(realmName, getFlowInList(name, topLevelActualFlows))
//		if err != nil {
//			actionLogger.Info(fmt.Sprintf("Unable to delete authentication flow. ID: %s, Alias: %s", getFlowInList(name, topLevelActualFlows).ID, name))
//			return err
//		}
	}
	for _, name := range flowsToAdd {
		actionLogger.Info(fmt.Sprintf("Adding Authentication Flow: %s", name))
		flow := getFlowInList(name, allDesiredFlows)
		uid, err := i.keycloakClient.CreateAuthenticationFlow(realmName, flow)
		if err != nil {
			actionLogger.Info(fmt.Sprintf("Error: Unable to create authentication flow: %s", name))
			return err
		}
		
		// Can you write ID into CR here?
		flow.ID = uid
	}
	for _, name := range flowsToCompare {
		actionLogger.Info(fmt.Sprintf("Compare: %s", name))
		aflow := getFlowInListOfPointers(name, topLevelActualFlows)
		dflow := getFlowInList(name, allDesiredFlows)
		if deepCompareAuthFlows(dflow, aflow, allDesiredFlows) {
			actionLogger.Info(fmt.Sprintf("%s is diff. %s/%s", name, aflow.ID, dflow.ID))
			err := i.keycloakClient.UpdateAuthenticationFlow(realmName, dflow)
			if err != nil {
				actionLogger.Info(fmt.Sprintf("Error: Unable to update authentication flow: %s", name))
				return err
			}
		}
	}
	
	return nil
}

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

/*
* PRIVATE LOGIC FUNCTIONS
*/

/** 
 * dflow: A pointer to the desired KeycloakAPIAuthenticationFlow state, from the CR definition
 * aflow: A pointer to the current KeycloakAPIAuthenticationFlow state, queried from the Keycloak API.
 * allDesiredFlows: The full list of desired flows form the CR definition, used to recurse into sub-flows.
 * 
 * Performs a deep comparison between the "current authentication flow" state, represented as `aflow`, and the "desired authentication flow" state, represented as `dflow`.
 * 1. First, compares top level attributes `ProviderID` and `Description`. KeycloakAPIAuthenticationFlow attributes `TopLevel` and `BuiltIn` are currently ignored when comparing.
 * 2. Next, sort the `AuthenticationExecution` list from the desired and actual flow by `Priority`, which indicates their intended execution order.
 * 3. Next, for each `AuthenticationExecution` child in the desired flow compare it to the oject in the actual flow at the same position.
 *   a. Compare the attributes `Authenticator`, `AuthenticatorConfig`, `AuthenticatorFlow`, `Priority`, `Requiernment`, and `UserSetupAllowed` for differences.
 *   b. If the `AuthenticationExecution` is a sub-flow, fetch the desired (from allDesiredFlows) and actual (from keycloak API) and recursively compare.
 *
 * "Fails fast" and returns true after the first difference is detected.
**/
func deepCompareAuthFlows(dflow *v1alpha1.KeycloakAPIAuthenticationFlow, aflow *v1alpha1.KeycloakAPIAuthenticationFlow, allDesiredFlows []v1alpha1.KeycloakAPIAuthenticationFlow) bool {
	currentAliasName := dflow.Alias

	// Test junk
	dSubJson, err := json.Marshal(dflow)
	if err != nil {
		log.Error(err, "Error trying to marshal dflow.")
	}
	aSubJson, err := json.Marshal(aflow)
	if err != nil {
		log.Error(err, "Error trying to marshal aflow.")
	}
	log.Info(fmt.Sprintf("dlow \"%v/%s\".", currentAliasName, dSubJson))
	log.Info(fmt.Sprintf("alow \"%v/%s\".", currentAliasName, aSubJson))
	// End test junk
	
	log.Info(fmt.Sprintf("Desired %v Description: %v", currentAliasName, dflow.Description))
	log.Info(fmt.Sprintf("Actual  %v Description: %v", currentAliasName, aflow.Description))
	log.Info(fmt.Sprintf("Desired %v ProviderID: %v", currentAliasName, dflow.ProviderID))
	log.Info(fmt.Sprintf("Actual  %v ProviderID: %v", currentAliasName, aflow.ProviderID))
	
	// Step 1
	if dflow.Description != aflow.Description || dflow.ProviderID != aflow.ProviderID {
		log.Info(fmt.Sprintf("Diff found in %v. Different Description or ProviderID.", currentAliasName))
		return true
	}
	
	// Step 2
	if len(aflow.AuthenticationExecutions) != len(dflow.AuthenticationExecutions) {
		log.Info(fmt.Sprintf("Diff found in %v. Different number of AuthenticationExecutions.", currentAliasName))
		return true
	}
	sort.Slice(aflow.AuthenticationExecutions, func(i, j int) bool {
		return aflow.AuthenticationExecutions[i].Priority < aflow.AuthenticationExecutions[j].Priority
	})
	sort.Slice(dflow.AuthenticationExecutions, func(i, j int) bool {
		return dflow.AuthenticationExecutions[i].Priority < dflow.AuthenticationExecutions[j].Priority
	})
	
	// Step 3
	for i, dExecution := range dflow.AuthenticationExecutions {
		aExecution := aflow.AuthenticationExecutions[i]
		log.Info(fmt.Sprintf("Desired \"%v/%v\" Priority: %v", currentAliasName, i, dExecution.Priority))
		log.Info(fmt.Sprintf("Actual  \"%v/%v\" Priority: %v", currentAliasName, i, aExecution.Priority))
		log.Info(fmt.Sprintf("Desired \"%v/%v\" Authenticator: %v", currentAliasName, i, dExecution.Authenticator))
		log.Info(fmt.Sprintf("Actual  \"%v/%v\" Authenticator: %v", currentAliasName, i, aExecution.Authenticator))
		log.Info(fmt.Sprintf("Desired \"%v/%v\" AuthenticatorConfig: %v", currentAliasName, i, dExecution.AuthenticatorConfig))
		log.Info(fmt.Sprintf("Actual  \"%v/%v\" AuthenticatorConfig: %v", currentAliasName, i, aExecution.AuthenticatorConfig))
		log.Info(fmt.Sprintf("Desired \"%v/%v\" AuthenticatorFlow: %v", currentAliasName, i, dExecution.AuthenticatorFlow))
		log.Info(fmt.Sprintf("Actual  \"%v/%v\" AuthenticatorFlow: %v", currentAliasName, i, aExecution.AuthenticatorFlow))
		log.Info(fmt.Sprintf("Desired \"%v/%v\" FlowAlias: %v", currentAliasName, i, dExecution.FlowAlias))
		log.Info(fmt.Sprintf("Actual  \"%v/%v\" FlowAlias: %v", currentAliasName, i, aExecution.FlowAlias))
		log.Info(fmt.Sprintf("Desired \"%v/%v\" Requirement: %v", currentAliasName, i, dExecution.Requirement))
		log.Info(fmt.Sprintf("Actual  \"%v/%v\" Requirement: %v", currentAliasName, i, aExecution.Requirement))
		log.Info(fmt.Sprintf("Desired \"%v/%v\" UserSetupAllowed: %v", currentAliasName, i, dExecution.UserSetupAllowed))
		log.Info(fmt.Sprintf("Actual  \"%v/%v\" UserSetupAllowed: %v", currentAliasName, i, aExecution.UserSetupAllowed))
		
		// Step 3A
		if dExecution.Priority != aExecution.Priority || dExecution.Authenticator != aExecution.Authenticator || dExecution.AuthenticatorConfig != aExecution.AuthenticatorConfig || dExecution.AuthenticatorFlow != aExecution.AuthenticatorFlow || dExecution.FlowAlias != aExecution.FlowAlias || dExecution.Requirement != aExecution.Requirement || dExecution.UserSetupAllowed != aExecution.UserSetupAllowed {
				log.Info(fmt.Sprintf("Diff found in \"%v/%v\".", currentAliasName, i))
				return true
		}
		
		// Step 3B
		if dExecution.AuthenticatorFlow == true {
			subFlowAlias := dExecution.FlowAlias
			dSubFlow := getFlowInList(subFlowAlias, allDesiredFlows)
			aSubFlow, err := i.keycloakClient.ListAuthenticationFlow(realmName, subFlowAlias)
			if err != nil {
				log.Error(err, "Error trying to retrieve sub-flow.")
			}
			// Test junk
			dSubFlowJson, err := json.Marshal(dSubFlow)
			if err != nil {
				log.Error(err, "Error trying to marshal dsubflow.")
			}
			aSubFlowJson, err := json.Marshal(aSubFlow)
			if err != nil {
				log.Error(err, "Error trying to marshal asubflow.")
			}
			log.Info(fmt.Sprintf("dSubFlow \"%v/%s\".", subFlowAlias, dSubFlowJson))
			log.Info(fmt.Sprintf("aSubFlow \"%v/%s\".", subFlowAlias, aSubFlowJson))
			// End test junk
			childDiff := deepCompareAuthFlows(dSubFlow, aSubFlow, allDesiredFlows) //recurse
			if childDiff {
				log.Info(fmt.Sprintf("Diff found in \"%v/%v\".", currentAliasName, i))
				return true
			}
		}
	}

	
	return false
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

// union returns the all elements in `a` and all the elments in `b` (no duplicates)
func union(a, b []string) []string {
	check := make(map[string]int)
	d := append(a, b...)
	union := make([]string, 0)
	for _, val := range d {
		check[val] = 1
	}

	for letter, _ := range check {
		union = append(union, letter)
	}

	return union
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
