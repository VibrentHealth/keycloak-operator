package common

import (
	"context"
	"fmt"
	"reflect"
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
	ApplyOverrides(obj *v1alpha1.KeycloakRealm) error
	UpdateRealmRoles(obj *v1alpha1.KeycloakRealm) error
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

/*
* Configure Realm Roles. Includes configuring composites under roles.realm.composites.
* Does not include roles.client.additionalProperties configuration.
 */

func (i *ClusterActionRunner) configureRealmRoles(obj *v1alpha1.KeycloakRealm) error {
	realmName := obj.Spec.Realm.Realm

	// get top level actual roles
	topLevelActualRoles, err := i.keycloakClient.ListRealmRoles(realmName)
	if err != nil {
		return err
	}

	// get IDs and match them with role names
	topLevelNamesIDs := make(map[string]string)
	for _, topLevelRole := range topLevelActualRoles {
		topLevelNamesIDs[topLevelRole.Name] = topLevelRole.ID
	}

	rolesToRemove := difference(getActualRoleNames(topLevelActualRoles), getDesiredRoleNames(getAllDesiredRealmRoles(obj)))
	rolesToAdd := difference(getDesiredRoleNames(getAllDesiredRealmRoles(obj)), getActualRoleNames(topLevelActualRoles))
	rolesToCompare := difference(union(getActualRoleNames(topLevelActualRoles), getDesiredRoleNames(getAllDesiredRealmRoles(obj))), append(rolesToAdd, rolesToRemove...))

	// UPDATE REALM ROLES LOGIC
	err2 := i.realmRolesUpdate(obj, rolesToCompare, topLevelActualRoles, topLevelNamesIDs)
	if err2 != nil {
		return err2
	}

	// REMOVE REALM ROLES LOGIC
	err3 := i.realmRolesRemove(obj, rolesToRemove, topLevelNamesIDs)
	if err3 != nil {
		return err3
	}

	// REMOVE REALM ROLES LOGIC
	err4 := i.realmRolesAdd(obj, rolesToAdd)
	if err4 != nil {
		return err4
	}

	return nil
}

// UPDATE REALM ROLES LOGIC
func (i *ClusterActionRunner) realmRolesUpdate(obj *v1alpha1.KeycloakRealm, rolesToCompare []string, topLevelActualRoles []*v1alpha1.RoleRepresentation, topLevelNamesIDs map[string]string) error {
	actionLogger := log.WithValues("Request.Namespace", obj.Namespace, "Request.Name", obj.Name)
	realmName := obj.Spec.Realm.Realm
	for _, name := range rolesToCompare {
		actionLogger.Info(fmt.Sprintf("Compare: %s", name))
		arole := getRoleInListOfPointers(name, topLevelActualRoles)
		drole := getRealmRoleInList(name, getAllDesiredRealmRoles(obj))
		if !genericEqualsRealmRoles(drole, arole) {
			actionLogger.Info(fmt.Sprintf("Updating Realm Role: %s", name))
			err := i.keycloakClient.UpdateRealmRole(drole, realmName, arole.ID)
			if err != nil {
				actionLogger.Info(fmt.Sprintf("Error: Unable to update realm role: %s", name))
				return err
			}
		}

		aroleComposites, err := i.keycloakClient.ListRealmRoleComposites(realmName, arole.ID)
		if err != nil {
			return err
		}
		aroleCompositesLength := len(aroleComposites)
		droleCompositesLength := getdroleCompositesLength(drole)

		actionLogger.Info(fmt.Sprintf("Checking Composites for Realm Role: %s", name))
		// add realm role composites
		if droleCompositesLength > aroleCompositesLength {
			actionLogger.Info(fmt.Sprintf("Adding role Composites to Realm Role: %s", name))
			err := i.keycloakClient.AddRealmRoleComposites(realmName, arole.ID, getDesiredRoleCompositesToAdd(topLevelNamesIDs, drole.Composites.Realm))
			if err != nil {
				actionLogger.Info(fmt.Sprintf("Error: Unable to add composites for realm role: %s", name))
				return err
			}
		}
		// remove realm role composites
		if droleCompositesLength < aroleCompositesLength {
			actionLogger.Info(fmt.Sprintf("Removing role Composites from Realm Role: %s", name))
			err := i.keycloakClient.DeleteRealmRoleComposites(realmName, arole.ID, getDesiredRoleCompositesToRemove(aroleComposites, drole))
			if err != nil {
				actionLogger.Info(fmt.Sprintf("Error: Unable to remove composites for realm role: %s", name))
				return err
			}
		}
		// update realm role composites
		if droleCompositesLength == aroleCompositesLength && aroleCompositesLength != 0 {
			err := i.updateEqualLengthRoleComposites(obj, aroleComposites, arole, drole, topLevelNamesIDs, name)
			if err != nil {
				actionLogger.Info(fmt.Sprintf("Error: Unable to remove composites for realm role: %s", name))
				return err
			}
		}
	}
	return nil
}

// get desired role composites length
func getdroleCompositesLength(drole *v1alpha1.RoleRepresentation) int {
	droleCompositesLength := 0
	if drole.Composites != nil {
		if drole.Composites.Realm != nil {
			droleCompositesLength = len(drole.Composites.Realm)
		}
	}
	return droleCompositesLength
}

// update logic for equal amount of composites in actual and desired roles
func (i *ClusterActionRunner) updateEqualLengthRoleComposites(obj *v1alpha1.KeycloakRealm, aroleComposites []*v1alpha1.RoleRepresentation, arole *v1alpha1.RoleRepresentation, drole *v1alpha1.RoleRepresentation, topLevelNamesIDs map[string]string, name string) error {
	actionLogger := log.WithValues("Request.Namespace", obj.Namespace, "Request.Name", obj.Name)
	realmName := obj.Spec.Realm.Realm
	aroleCompositeNames := []string{}
	for _, aroleComposite := range aroleComposites {
		aroleCompositeNames = append(aroleCompositeNames, aroleComposite.Name)
	}
	droleCompositeNames := drole.Composites.Realm
	sort.Strings(aroleCompositeNames)
	sort.Strings(droleCompositeNames)
	if !reflect.DeepEqual(aroleCompositeNames, droleCompositeNames) {
		actionLogger.Info(fmt.Sprintf("Updating role Composites in Realm Role: %s", name))
		roleCompositesToAdd, roleCompositesToRemove := getRoleCompositesToUpdate(aroleComposites, drole.Composites.Realm, topLevelNamesIDs)
		err := i.keycloakClient.DeleteRealmRoleComposites(realmName, arole.ID, roleCompositesToRemove)
		if err != nil {
			actionLogger.Info(fmt.Sprintf("Error: Unable to remove composites for realm role: %s", name))
			return err
		}
		err2 := i.keycloakClient.AddRealmRoleComposites(realmName, arole.ID, roleCompositesToAdd)
		if err2 != nil {
			actionLogger.Info(fmt.Sprintf("Error: Unable to add composites for realm role: %s", name))
			return err2
		}
	}
	return nil
}

// REMOVE REALM ROLES LOGIC
func (i *ClusterActionRunner) realmRolesRemove(obj *v1alpha1.KeycloakRealm, rolesToRemove []string, topLevelNamesIDs map[string]string) error {
	actionLogger := log.WithValues("Request.Namespace", obj.Namespace, "Request.Name", obj.Name)
	realmName := obj.Spec.Realm.Realm
	for _, name := range rolesToRemove {
		roleID := topLevelNamesIDs[name]
		rolesToIgnore := []string{"default-roles-" + realmName}
		if !contains(rolesToIgnore, name) {
			actionLogger.Info(fmt.Sprintf("Removing Realm Role: %s", name))
			err := i.keycloakClient.DeleteRealmRole(realmName, roleID)
			if err != nil {
				actionLogger.Info(fmt.Sprintf("Unable to delete realm role. ID: %s, Name: %s", roleID, name))
				return err
			}
		}
	}
	return nil
}

// REMOVE REALM ROLES LOGIC
func (i *ClusterActionRunner) realmRolesAdd(obj *v1alpha1.KeycloakRealm, rolesToAdd []string) error {
	actionLogger := log.WithValues("Request.Namespace", obj.Namespace, "Request.Name", obj.Name)
	realmName := obj.Spec.Realm.Realm
	for _, name := range rolesToAdd {
		actionLogger.Info(fmt.Sprintf("Adding Realm Role: %s", name))
		role := getRealmRoleInList(name, getAllDesiredRealmRoles(obj))
		err := i.keycloakClient.CreateRealmRole(role, realmName)
		if err != nil {
			actionLogger.Info(fmt.Sprintf("Error: Unable to create realm role: %s", name))
			return err
		}
	}
	return nil
}

// Compare actual realm roles vs desired realm roles by basic components
func genericEqualsRealmRoles(drole *v1alpha1.RoleRepresentation, arole *v1alpha1.RoleRepresentation) bool {
	return arole.Description == drole.Description && arole.Name == drole.Name && reflect.DeepEqual(arole.Attributes, drole.Attributes)
}

// Get all desired realm roles from the CR
func getAllDesiredRealmRoles(obj *v1alpha1.KeycloakRealm) []v1alpha1.RoleRepresentation {
	desiredRealmRoles := []v1alpha1.RoleRepresentation{}
	if obj.Spec.Realm.Roles != nil {
		if obj.Spec.Realm.Roles.Realm != nil {
			desiredRealmRoles = obj.Spec.Realm.Roles.Realm
		}
	}
	return desiredRealmRoles
}

// Get actual role names based on actual realm roles
func getActualRoleNames(topLevelActualRoles []*v1alpha1.RoleRepresentation) []string {
	actualRoleNames := []string{}
	for _, arole := range topLevelActualRoles {
		actualRoleNames = append(actualRoleNames, arole.Name)
	}
	return actualRoleNames
}

// Get desired role names based on desired roles
func getDesiredRoleNames(desiredRoles []v1alpha1.RoleRepresentation) []string {
	desiredRoleNames := []string{}
	for _, drole := range desiredRoles {
		desiredRoleNames = append(desiredRoleNames, drole.Name)
	}
	return desiredRoleNames
}

// Get desired role composite roles that need to be added
func getDesiredRoleCompositesToAdd(topLevelNamesIDs map[string]string, desiredRoleCompositeNames []string) *[]v1alpha1.RoleRepresentation {
	desiredRoleComposites := []v1alpha1.RoleRepresentation{}
	for _, desiredRoleCompositeName := range desiredRoleCompositeNames {
		desiredRoleComposite := v1alpha1.RoleRepresentation{}
		desiredRoleComposite.Name = desiredRoleCompositeName
		desiredRoleComposite.ID = topLevelNamesIDs[desiredRoleCompositeName]
		desiredRoleComposites = append(desiredRoleComposites, desiredRoleComposite)
	}
	return &desiredRoleComposites
}

// Get desired role composite roles that need to be removed
func getDesiredRoleCompositesToRemove(aroleComposites []*v1alpha1.RoleRepresentation, drole *v1alpha1.RoleRepresentation) *[]v1alpha1.RoleRepresentation {
	desiredRoleComposites := []v1alpha1.RoleRepresentation{}

	if drole.Composites == nil {
		for _, actualRoleCompositeName := range aroleComposites {
			desiredRoleComposite := v1alpha1.RoleRepresentation{}
			desiredRoleComposite.Name = actualRoleCompositeName.Name
			desiredRoleComposite.ID = actualRoleCompositeName.ID
			desiredRoleComposites = append(desiredRoleComposites, desiredRoleComposite)
		}
		return &desiredRoleComposites
	}

	for _, actualRoleCompositeName := range aroleComposites {
		if !contains(drole.Composites.Realm, actualRoleCompositeName.Name) {
			desiredRoleComposite := v1alpha1.RoleRepresentation{}
			desiredRoleComposite.Name = actualRoleCompositeName.Name
			desiredRoleComposite.ID = actualRoleCompositeName.ID
			desiredRoleComposites = append(desiredRoleComposites, desiredRoleComposite)
		}
	}
	return &desiredRoleComposites
}

// Get composite roles that need to be updated. Added and removed.
func getRoleCompositesToUpdate(aroleComposites []*v1alpha1.RoleRepresentation, desiredRoleCompositeNames []string, topLevelNamesIDs map[string]string) (*[]v1alpha1.RoleRepresentation, *[]v1alpha1.RoleRepresentation) {
	desiredRoleCompositesToAdd := []v1alpha1.RoleRepresentation{}
	desiredRoleCompositesToRemove := []v1alpha1.RoleRepresentation{}
	aroleCompositeNames := []string{}
	for _, aroleComposite := range aroleComposites {
		aroleCompositeNames = append(aroleCompositeNames, aroleComposite.Name)
		if !contains(desiredRoleCompositeNames, aroleComposite.Name) {
			desiredRoleCompositeToRemove := v1alpha1.RoleRepresentation{}
			desiredRoleCompositeToRemove.Name = aroleComposite.Name
			desiredRoleCompositeToRemove.ID = aroleComposite.ID
			desiredRoleCompositesToRemove = append(desiredRoleCompositesToRemove, desiredRoleCompositeToRemove)
		}
	}
	for _, droleCompositeName := range desiredRoleCompositeNames {
		if !contains(aroleCompositeNames, droleCompositeName) {
			desiredRoleCompositeToAdd := v1alpha1.RoleRepresentation{}
			desiredRoleCompositeToAdd.Name = droleCompositeName
			desiredRoleCompositeToAdd.ID = topLevelNamesIDs[droleCompositeName]
			desiredRoleCompositesToAdd = append(desiredRoleCompositesToAdd, desiredRoleCompositeToAdd)
		}
	}
	return &desiredRoleCompositesToAdd, &desiredRoleCompositesToRemove
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

// contains function
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

// Look up realm role in a list by it's name
func getRealmRoleInList(name string, list []v1alpha1.RoleRepresentation) *v1alpha1.RoleRepresentation {
	for _, val := range list {
		if val.Name == name {
			return &val
		}
	}
	return nil
}

// Look up realm role in a list by it's name
func getRoleInListOfPointers(name string, list []*v1alpha1.RoleRepresentation) *v1alpha1.RoleRepresentation {
	for _, val := range list {
		if val.Name == name {
			return val
		}
	}
	return nil
}

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
