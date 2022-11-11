package common

import (
	"context"
	"fmt"

	kc "github.com/keycloak/keycloak-operator/pkg/apis/keycloak/v1alpha1"
	"github.com/keycloak/keycloak-operator/pkg/model"
	v1 "k8s.io/api/core/v1"
	apiErrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

var vibrentClientStateLog = logf.Log.WithName("vibrent_client_state")

type ClientState struct {
	Client                  *kc.KeycloakAPIClient
	ClientSecret            *v1.Secret // keycloak-client-secret-<custom resource name>
	Context                 context.Context
	Realm                   *kc.KeycloakRealm
	Roles                   []kc.RoleRepresentation
	DefaultRoleID           string
	DefaultRoles            []kc.RoleRepresentation
	ScopeMappings           *kc.MappingsRepresentation
	AvailableClientScopes   []kc.KeycloakClientScope
	DefaultClientScopes     []kc.KeycloakClientScope
	OptionalClientScopes    []kc.KeycloakClientScope
	DeprecatedClientSecret  *v1.Secret // keycloak-client-secret-<clientID>
	Keycloak                kc.Keycloak
	ServiceAccountUserState *UserState
}

func NewClientState(context context.Context, realm *kc.KeycloakRealm, keycloak kc.Keycloak) *ClientState {
	return &ClientState{
		Context:  context,
		Realm:    realm,
		Keycloak: keycloak,
	}
}

func (i *ClientState) Read(context context.Context, cr *kc.KeycloakClient, realmClient KeycloakInterface, controllerClient client.Client) error {
	// Vibrent code, AC-120153
	// This function is responsible for building a model of the client (defined on L13 and referred to in this function as i) based on the
	// the actual state in keycloak. The upstream repository's behavior is to lookup the existing client by it's GUID ID, present in
	// `cr.Spec.Client.ID` only when the operator previously created the client in keycloak.
	//
	// In the new behavior, if `cr.Spec.Client.ID` is empty, first a query of all clients present is done. If a matching client is found by
	// `cr.Spec.Client.ClientID`, then it's ID is added to the spec and the process is allowed to continue.
	if cr.Spec.Client.ID == "" {
		vibrentClientStateLog.Info(fmt.Sprintf("Empty Client.ID found for %v/%v. Doing lookup by name.", i.Realm.Spec.Realm.Realm, cr.Spec.Client.ClientID))
		allClients, err := realmClient.ListClients(i.Realm.Spec.Realm.Realm)

		if err != nil {
			vibrentClientStateLog.Error(err, fmt.Sprintf("Error fetching all clients for %v/%v.", i.Realm.Spec.Realm.Realm, cr.Spec.Client.ClientID))
			return err
		}

		for _, c := range allClients {
			if c.ClientID == cr.Spec.Client.ClientID {
				vibrentClientStateLog.Info(fmt.Sprintf("Found matching client for %v/%v with ID %v", i.Realm.Spec.Realm.Realm, cr.Spec.Client.ClientID, c.ID))
				cr.Spec.Client.ID = c.ID
				break
			}
		}
	}

	// If the new logic did not set `cr.Spec.Client.ID`, then return nil like original behavior did.
	if cr.Spec.Client.ID == "" {
		vibrentClientStateLog.Info(fmt.Sprintf("No exisiting client found for %v/%v", i.Realm.Spec.Realm.Realm, cr.Spec.Client.ClientID))
		return nil
	}

	// Now `cr.Spec.Client.ID` must exist and there was a pre-existing or merged match found. We will fetch it directly to get full object.
	vibrentClientStateLog.Info(fmt.Sprintf("Client has existing ID for %v/%v: %v", i.Realm.Spec.Realm.Realm, cr.Spec.Client.ClientID, cr.Spec.Client.ID))
	client, err := realmClient.GetClient(cr.Spec.Client.ID, i.Realm.Spec.Realm.Realm)

	if err != nil {
		return err
	}

	i.Client = client

	// CR could have updated with new secret, so set saved secret to Spec only when empty
	// Otherwise let reconcile loop to update secret with desired secret in CR
	if cr.Spec.Client.Secret == "" {
		clientSecret, err := realmClient.GetClientSecret(cr.Spec.Client.ID, i.Realm.Spec.Realm.Realm)
		if err != nil {
			return err
		}

		cr.Spec.Client.Secret = clientSecret
	}

	err = i.readClientSecret(context, cr, i.Client, controllerClient)
	if err != nil {
		return err
	}

	if cr.Name != cr.Spec.Client.ClientID {
		// only read when these fields aren't equal to avoid unwanted cyclical create / delete of client secret
		err = i.readDepcreatedClientSecret(context, cr, i.Client, controllerClient)
		if err != nil {
			return err
		}
	}

	if i.Client == nil {
		return nil
	}

	i.Roles, err = realmClient.ListClientRoles(cr.Spec.Client.ID, i.Realm.Spec.Realm.Realm)
	if err != nil {
		return err
	}

	i.ScopeMappings, err = realmClient.ListScopeMappings(cr.Spec.Client.ID, i.Realm.Spec.Realm.Realm)
	if err != nil {
		return err
	}

	err = i.readClientScopes(cr, realmClient)
	if err != nil {
		return err
	}

	err = i.readDefaultRoles(cr, realmClient)
	if err != nil {
		return err
	}

	if i.Client.ServiceAccountsEnabled {
		user, err := realmClient.GetServiceAccountUser(i.Realm.Spec.Realm.Realm, cr.Spec.Client.ID)
		if err != nil {
			return err
		}

		i.ServiceAccountUserState = NewUserState(i.Keycloak)
		err = i.ServiceAccountUserState.ReadWithExistingAPIUser(realmClient, controllerClient, user, *i.Realm)
		if err != nil {
			return err
		}
	}

	return nil
}

func (i *ClientState) readClientScopes(cr *kc.KeycloakClient, realmClient KeycloakInterface) (err error) {
	// It is not strictly a property of the client but rather of the realm.
	// However could not figure out a better way to convey it to populate default and optional
	// client scopes which requires client scope IDs.
	i.AvailableClientScopes, err = realmClient.ListRealmClientScopes(i.Realm.Spec.Realm.Realm)
	if err != nil {
		return err
	}

	i.DefaultClientScopes, err = realmClient.ListDefaultClientScopes(cr.Spec.Client.ID, i.Realm.Spec.Realm.Realm)
	if err != nil {
		return err
	}

	i.OptionalClientScopes, err = realmClient.ListOptionalClientScopes(cr.Spec.Client.ID, i.Realm.Spec.Realm.Realm)
	if err != nil {
		return err
	}
	return nil
}

func (i *ClientState) readClientSecret(context context.Context, cr *kc.KeycloakClient, clientSpec *kc.KeycloakAPIClient, controllerClient client.Client) error {
	key := model.ClientSecretSelector(cr)
	secret := model.ClientSecret(cr)

	err := controllerClient.Get(context, key, secret)
	if err != nil {
		if !apiErrors.IsNotFound(err) {
			return err
		}
	} else {
		i.ClientSecret = secret.DeepCopy()
		cr.UpdateStatusSecondaryResources(i.ClientSecret.Kind, i.ClientSecret.Name)
	}
	return nil
}

func (i *ClientState) readDefaultRoles(cr *kc.KeycloakClient, realmClient KeycloakInterface) error {
	// we can't use state.Realm as it is the CR, not actual Realm state, and is missing defaultRole
	realm, err := realmClient.GetRealm(i.Realm.Spec.Realm.Realm)
	if err != nil {
		return err
	}

	i.DefaultRoleID = realm.Spec.Realm.DefaultRole.ID
	i.DefaultRoles, err = realmClient.ListRealmRoleClientRoleComposites(i.Realm.Spec.Realm.Realm, i.DefaultRoleID, cr.Spec.Client.ID)
	return err
}

// Read client secret created using the previous naming scheme, i.e., keycloak-client-secret-<CLIENT_ID>.
// See GH issue #473 and KEYCLOAK-18346.
func (i *ClientState) readDepcreatedClientSecret(context context.Context, cr *kc.KeycloakClient, clientSpec *kc.KeycloakAPIClient, controllerClient client.Client) error {
	key := model.DeprecatedClientSecretSelector(cr)
	secret := model.DeprecatedClientSecret(cr)

	err := controllerClient.Get(context, key, secret)
	if err != nil {
		if !apiErrors.IsNotFound(err) {
			return err
		}
	} else {
		i.DeprecatedClientSecret = secret.DeepCopy()
	}

	// delete reference to keycloak-client-secret-<CLIENT_ID> in secondary resources
	cr.DeleteFromStatusSecondaryResources(secret.Kind, secret.Name)

	return nil
}
