package common

import (
	"context"
	"fmt"
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


/**
 * Concepts of auth flows and how they are nested:
 *  * An authentication flow contains a unique name (alias) and an ordered list of execution steps.
 *  * An execution step is represented in the KC admin UI by a single table row. It contains a requirement level, and is either type "authenticator" or "sub-flow" based on the boolean value `authenticatorFlow`.
 *    * If an execution step is an authenticator, it contains a reference to a provider java class in KC (by name), and optional configuration for using the provider class.
 *    * If an execution step is a sub-flow, it contains a name, description, and a reference to an authentication flow object (by flowID, not alias)
 *  * An authentication flow has a boolean field `topLevel`. IF topLevel == false, the flow is a sub-flow and is referenced by some execution step. IF topLevel == true, the flow can be set as the start point for one of the core authentication paths (login, registration, password reset, etc)
 *
 *
 * Start of logic to diff the "desired state" of authentication flows parsed from the KeycloakRealm CR against the "actual state" queried from the KC admin
 * api. This logic compares all custom top-level flows, comparing each execution step and recursively comparing sub-flows.
 *
 * Is only capable of issuing selected updates to each auth flow, due to time constraints and the complexity of the KC API for authentication flows. The API is
 * defined in the upstream keycloak respository at AuthenticationManagementResource.java
 *
 * Supported Changes:
 *   * Update requirenment level of an execution step.
 *   * When execution step is type sub-flow:
 *     * Update to the sub-flow's name (alias)
 *
 *
 * Unsupported:
 *   * Any management of the "built-in" flows.
 *   * Deletion of exisitng top-level flow (will be logged by operator, but not removed from KC.)
 *   * Creation of new top-level flow (will be logged by operator, but not created in KC.)
 *   * Changing an execution's type from "authenticator type" to "sub-flow type" or vice versa (updates to authenticatorFlow boolean value)
 *   * Re-ordering execution steps based on updated Priority
 *   * When execution step is type authenticator (and NOT a sub-flow):
 *     * Changing the provider class referenced by the authenticator (not supported by KC API, requires delete + recreate)
 *   * When execution step is type sub-flow:
 *     * Changing the description. Field is missing from v1alpha1.AuthenticationExecutionInfo use for execution PUT request.
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
		if dflow.TopLevel == true && dflow.BuiltIn != true {
			desiredFlowNames = append(desiredFlowNames, dflow.Alias)
		}
	}
	for _, aflow := range topLevelActualFlows {
		if aflow.TopLevel == true && aflow.BuiltIn != true {
			actualFlowNames = append(actualFlowNames, aflow.Alias)
		}
	}
	
	// Categorize Top Level Comparisons
	flowsToRemove := difference(actualFlowNames, desiredFlowNames)
	flowsToAdd := difference(desiredFlowNames, actualFlowNames)
	flowsToCompare := difference(union(actualFlowNames, desiredFlowNames), append(flowsToAdd, flowsToRemove...))
	
	// Do updates
	for _, name := range flowsToRemove {
		actionLogger.Info(fmt.Sprintf("WARNING: Deleting top level authentication flow %s is not supported.", name))
//		actionLogger.Info(fmt.Sprintf("Removing Authentication Flow: %s", name))
//		err := i.keycloakClient.DeleteAuthenticationFlow(realmName, getFlowInList(name, topLevelActualFlows))
//		if err != nil {
//			actionLogger.Info(fmt.Sprintf("Unable to delete authentication flow. ID: %s, Alias: %s", getFlowInList(name, topLevelActualFlows).ID, name))
//			return err
//		}
	}
	for _, name := range flowsToAdd {
		actionLogger.Info(fmt.Sprintf("WARNING: Creating top level authentication flow %s is not supported.", name))
//		flow := getFlowInList(name, allDesiredFlows)
//		uid, err := i.keycloakClient.CreateAuthenticationFlow(realmName, flow)
//		if err != nil {
//			actionLogger.Info(fmt.Sprintf("Error: Unable to create authentication flow: %s", name))
//			return err
//		}
//		
//		// Can you write ID into CR here?
//		flow.ID = uid
	}
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
 * "Fails fast" and returns true after the first difference is detected.
**/
func (i *ClusterActionRunner) recursivelyReconcileAuthFlow(realmName string, dflowQualifiedName string, dflow *v1alpha1.KeycloakAPIAuthenticationFlow, aflow *v1alpha1.KeycloakAPIAuthenticationFlow, allDesiredFlows []v1alpha1.KeycloakAPIAuthenticationFlow, allActualExecutionInfos []*v1alpha1.AuthenticationExecutionInfo, actionLogger logr.Logger) error {
	topLevelFlowName := strings.Split(dflowQualifiedName, " -> ")[0]
	flowLogger := actionLogger.WithValues("Realm.TopLevelFlow", topLevelFlowName, "Realm.Flow.SubFlow", dflowQualifiedName)

	// Test junk
	dSubJson, err := json.Marshal(dflow)
	if err != nil {
		flowLogger.Error(err, "Error trying to marshal dflow.")
		return err
	}
	aSubJson, err := json.Marshal(aflow)
	if err != nil {
		flowLogger.Error(err, "Error trying to marshal aflow.")
		return err
	}
	flowLogger.Info(fmt.Sprintf("Comparing dFlow: [%v] - %s", dflowQualifiedName, dSubJson))
	flowLogger.Info(fmt.Sprintf("Comparing aFlow: [%v] - %s", dflowQualifiedName, aSubJson))
	// End test junk
	
	// Step 1
	if dflow.Description != aflow.Description || dflow.ProviderID != aflow.ProviderID {
		flowLogger.Info(fmt.Sprintf("[FLOW UPDATE] Different Description or ProviderID. Update by ID: %v", aflow.ID))
		dflow.ID = aflow.ID
		err := i.keycloakClient.UpdateAuthenticationFlow(realmName, dflow)
		if err != nil {
			flowLogger.Info(fmt.Sprintf("[FLOW UPDATE - ERROR] Unable to update authentication flow. Update by ID: %v", aflow.ID))
			return err
		}
	}
	
	// Step 2
	desiredExecutionStepNames := []string{}
	actualExecutionStepNames := []string{}
	for _, dstep := range dflow.AuthenticationExecutions {
		if dstep.AuthenticatorFlow == true {
			desiredExecutionStepNames = append(desiredExecutionStepNames, dstep.FlowAlias)
		} else {
			desiredExecutionStepNames = append(desiredExecutionStepNames, dstep.Authenticator)
		}
	}
	for _, astep := range aflow.AuthenticationExecutions {
		if astep.AuthenticatorFlow == true {
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
		flowLogger.Info(fmt.Sprintf("[FLOW UPDATE] Delete Execution Step. Delete by ID: %v", payloadID))
		err := i.keycloakClient.DeleteAuthenticationExecutionForFlow(realmName, payloadID)
		if err != nil {
			flowLogger.Info(fmt.Sprintf("[FLOW UPDATE - ERROR] Unable to remove execution step from authentication flow. Delete by ID: %v", payloadID))
			return err
		}
	}
	for _, executionName := range stepsToAdd {
		flowLogger.Info(fmt.Sprintf("[FLOW UPDATE - WARNING]: Creating new execution step %v from %v is not supported.", executionName, dflowQualifiedName))
	}
	
	// Step 4
	for _, executionName := range stepsToCompare {
		dExecution := getExecutionInList(executionName, dflow.AuthenticationExecutions)
		aExecution := getExecutionInList(executionName, aflow.AuthenticationExecutions)

		// Test junk
		dExecutionJson, err := json.Marshal(dExecution)
		if err != nil {
			flowLogger.Error(err, "Error trying to marshal dExecution.")
		}
		aExecutionJson, err := json.Marshal(aExecution)
		if err != nil {
			flowLogger.Error(err, "Error trying to marshal aExecutionJson.")
		}
		flowLogger.Info(fmt.Sprintf("Comparing dExecution: [%v] - %s", executionName, dExecutionJson))
		flowLogger.Info(fmt.Sprintf("Comparing aExecution: [%v] - %s", executionName, aExecutionJson))
		// End test junk
		
		// Step 4A - Test Requirement level
		if dExecution.Requirement != aExecution.Requirement {
				flowLogger.Info(fmt.Sprintf("[FLOW UPDATE] Set Requiernment Level to %v for AuthenticationExecution step %v", dExecution.Requirement, executionName))
				payload := v1alpha1.AuthenticationExecutionInfo{
					ID: getExecutionInfoInList(aExecution, allActualExecutionInfos).ID,
					Requirement: dExecution.Requirement,
				}
				
				err = i.keycloakClient.UpdateAuthenticationExecutionForFlow(dflow.Alias, realmName, &payload)
				if err != nil {
					flowLogger.Info(fmt.Sprintf("[FLOW UPDATE - ERROR] Unable to update requirement level. Update by ID: %v", payload.ID))
					return err
				}
		}
				
		// Step 4B - Retrieve and then recursively compare sub-flows.
		if dExecution.AuthenticatorFlow == true {
			subFlowAlias := dExecution.FlowAlias
			
			// dSubFlow just comes from the immutable list of all sub-flows defined in the CR
			dSubFlow := getFlowInList(subFlowAlias, allDesiredFlows)
			if dSubFlow == nil {
				return errors.Errorf("Referenced sub-flow [%v] is not defined in KeycloakRealm custom resource. Please check for CR defintion.", subFlowAlias)
			}
			
			// For aSubFlow you need to find the ExecutionInfo first from the immutable list of all the actual execution steps.
			// Then, retrieve FlowID from the ExecutionInfo object and query that sub-flow with Keycloak api call.
			aExecutionInfo := getExecutionInfoInList(aExecution, allActualExecutionInfos)
			if aExecutionInfo == nil {
				return errors.Errorf("Internal Error. Unable to find AuthenticationExecutionInfo obj with DisplayName %v in results from Keycloak API.", subFlowAlias)
			}
			
			// Test junk
			aExecutionInfoJson, err := json.Marshal(aExecutionInfo)
			if err != nil {
				flowLogger.Error(err, "Error trying to marshal aExecutionInfoJson.")
				return err
			}
			flowLogger.Info(fmt.Sprintf("Comparing aExecutionInfo: [%v] - %s", executionName, aExecutionInfoJson))
			// End test junk

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
		
		// Step 5 - Sorting
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
		log.Info(fmt.Sprintf("Input Authenticator Flow: %t, DisplayName: %s, ProviderID: %s", execution.AuthenticatorFlow, val.DisplayName, val.ProviderID))
		
		if execution.AuthenticatorFlow == true && val.DisplayName == execution.FlowAlias {
			return val
		}
		if execution.AuthenticatorFlow == false && val.ProviderID == execution.Authenticator {
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
