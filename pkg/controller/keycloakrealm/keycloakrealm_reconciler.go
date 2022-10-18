package keycloakrealm

import (
	"fmt"

	kc "github.com/keycloak/keycloak-operator/pkg/apis/keycloak/v1alpha1"
	"github.com/keycloak/keycloak-operator/pkg/common"
	"github.com/keycloak/keycloak-operator/pkg/model"

	"github.com/go-logr/logr"
)

type Reconciler interface {
	Reconcile(cr *kc.KeycloakRealm) error
}

type KeycloakRealmReconciler struct { // nolint
	Keycloak kc.Keycloak
}

func NewKeycloakRealmReconciler(keycloak kc.Keycloak) *KeycloakRealmReconciler {
	return &KeycloakRealmReconciler{
		Keycloak: keycloak,
	}
}

func (i *KeycloakRealmReconciler) Reconcile(state *common.RealmState, cr *kc.KeycloakRealm) common.DesiredClusterState {
	realmLogger := log.WithValues("Request.Namespace", cr.Namespace, "Request.Name", cr.Name)

	if cr.DeletionTimestamp == nil {
		return i.ReconcileRealmCreate(state, cr, realmLogger)
	}
	if cr.Spec.AllowRealmDeletion {
		realmLogger.Info("Deleting the realm. AllowRealmDeletion flag is set to true.")
		return i.ReconcileRealmDelete(state, cr, realmLogger)
	}
	realmLogger.Info("Realm is being orphaned, will not be deleted.")
	return nil
}

func (i *KeycloakRealmReconciler) ReconcileRealmCreate(state *common.RealmState, cr *kc.KeycloakRealm, realmLogger logr.Logger) common.DesiredClusterState {
	desired := common.DesiredClusterState{}

	desired.AddAction(i.getKeycloakDesiredState(cr))
	desired.AddAction(i.getDesiredRealmState(state, cr))

	for _, user := range cr.Spec.Realm.Users {
		desired.AddAction(i.getDesiredUserState(state, cr, user))
	}

	desired.AddAction(i.getBrowserRedirectorDesiredState(state, cr, realmLogger))
	desired.AddAction(i.getRealmRolesDesiredState(state, cr, realmLogger))

	return desired
}

func (i *KeycloakRealmReconciler) ReconcileRealmDelete(state *common.RealmState, cr *kc.KeycloakRealm, realmLogger logr.Logger) common.DesiredClusterState {
	desired := common.DesiredClusterState{}
	desired.AddAction(i.getKeycloakDesiredState(cr))
	desired.AddAction(i.getDesiredRealmState(state, cr))
	return desired
}

// Always make sure keycloak is able to respond
func (i *KeycloakRealmReconciler) getKeycloakDesiredState(cr *kc.KeycloakRealm) common.ClusterAction {
	return &common.PingAction{
		Msg: fmt.Sprintf("check if keycloak is available: %v/%v", cr.Namespace, cr.Spec.Realm.Realm),
	}
}

// Compare and issue necessary updates for realm roles
func (i *KeycloakRealmReconciler) getRealmRolesDesiredState(state *common.RealmState, cr *kc.KeycloakRealm, realmLogger logr.Logger) common.ClusterAction {
	// This step is not done when creating a new realm
	if state.Realm == nil {
		realmLogger.Info("Realm being created. Do not execute update realm roles logic.")
		return nil
	}

	return &common.UpdateRealmRolesAction{
		Ref: cr,
		Msg: fmt.Sprintf("configure realm roles: %v/%v", cr.Namespace, cr.Spec.Realm.Realm),
	}
}

// Configure the browser redirector if provided by the user
func (i *KeycloakRealmReconciler) getBrowserRedirectorDesiredState(state *common.RealmState, cr *kc.KeycloakRealm, realmLogger logr.Logger) common.ClusterAction {
	if len(cr.Spec.RealmOverrides) == 0 {
		return nil
	}

	// Never update the realm configuration, leave it up to the users
	if state.Realm != nil {
		return nil
	}

	return &common.ConfigureRealmAction{
		Ref: cr,
		Msg: fmt.Sprintf("configure browser redirector: %v/%v", cr.Namespace, cr.Spec.Realm.Realm),
	}
}

func (i *KeycloakRealmReconciler) getDesiredRealmState(state *common.RealmState, cr *kc.KeycloakRealm) common.ClusterAction {
	if cr.DeletionTimestamp != nil {
		return &common.DeleteRealmAction{
			Ref: cr,
			Msg: fmt.Sprintf("removing realm %v/%v", cr.Namespace, cr.Spec.Realm.Realm),
		}
	}

	if state.Realm == nil {
		return &common.CreateRealmAction{
			Ref: cr,
			Msg: fmt.Sprintf("create realm %v/%v", cr.Namespace, cr.Spec.Realm.Realm),
		}
	}

	return &common.UpdateRealmAction{
		Ref: cr,
		Msg: fmt.Sprintf("update realm %v/%v", cr.Namespace, cr.Spec.Realm.Realm),
	}
}

func (i *KeycloakRealmReconciler) getDesiredUserState(state *common.RealmState, cr *kc.KeycloakRealm, user *kc.KeycloakAPIUser) common.ClusterAction {
	val, ok := state.RealmUserSecrets[user.UserName]
	if !ok || val == nil {
		return &common.GenericCreateAction{
			Ref: model.RealmCredentialSecret(cr, user, &i.Keycloak),
			Msg: fmt.Sprintf("create credential secret for user %v in realm %v/%v", user.UserName, cr.Namespace, cr.Spec.Realm.Realm),
		}
	}

	return nil
}
