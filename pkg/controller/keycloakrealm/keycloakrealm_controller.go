package keycloakrealm

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/keycloak/keycloak-operator/pkg/k8sutil"

	"github.com/keycloak/keycloak-operator/pkg/apis/keycloak/v1alpha1"
	kc "github.com/keycloak/keycloak-operator/pkg/apis/keycloak/v1alpha1"
	"github.com/keycloak/keycloak-operator/pkg/common"
	corev1 "k8s.io/api/core/v1"
	kubeerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/go-logr/logr"
)

const (
	RealmFinalizer    = "realm.cleanup"
	RequeueDelayError = 1 * time.Minute
	ControllerName    = "controller_keycloakrealm"
)

var log = logf.Log.WithName(ControllerName)

/**
* USER ACTION REQUIRED: This is a scaffold file intended for the user to modify with their own Controller
* business logic.  Delete these comments after modifying this file.*
 */

// Add creates a new KeycloakRealm Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager) error {
	return add(mgr, newReconciler(mgr))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager) reconcile.Reconciler {
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	return &ReconcileKeycloakRealm{
		client:   mgr.GetClient(),
		scheme:   mgr.GetScheme(),
		cancel:   cancel,
		context:  ctx,
		recorder: mgr.GetEventRecorderFor(ControllerName),
	}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Retrieve MaxConcurrentReconciles from env variable. Default is 1.
	mcr, err := k8sutil.GetRealmMaxConcurrentReconciles()
	if err != nil {
		log.Error(err, "Failed to parse max concurrent reconciles for realm.")
		os.Exit(1)
	}

	// Create a new controller
	c, err := controller.New(ControllerName, mgr, controller.Options{Reconciler: r, MaxConcurrentReconciles: mcr})
	if err != nil {
		return err
	}

	// Watch for changes to primary resource KeycloakRealm
	err = c.Watch(&source.Kind{Type: &kc.KeycloakRealm{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	// Make sure to watch the credential secrets
	err = c.Watch(&source.Kind{Type: &corev1.Secret{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &kc.KeycloakRealm{},
	})
	if err != nil {
		return err
	}

	return nil
}

// blank assignment to verify that ReconcileKeycloakRealm implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcileKeycloakRealm{}

// ReconcileKeycloakRealm reconciles a KeycloakRealm object
type ReconcileKeycloakRealm struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client   client.Client
	scheme   *runtime.Scheme
	context  context.Context
	cancel   context.CancelFunc
	recorder record.EventRecorder
}

// Reconcile reads that state of the cluster for a KeycloakRealm object and makes changes based on the state read
// and what is in the KeycloakRealm.Spec
func (r *ReconcileKeycloakRealm) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	realmLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	realmLogger.Info(fmt.Sprintf("Reconciling KeycloakRealm %s/%s", request.Namespace, request.Name))

	// Fetch the KeycloakRealm instance
	instance := &kc.KeycloakRealm{}
	err := r.client.Get(context.TODO(), request.NamespacedName, instance)
	if err != nil {
		if kubeerrors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			realmLogger.Info("KeycloakRealm CR not found by kubernetes.")
			return reconcile.Result{}, nil
		}
		// Error reading the object - requeue the request.
		realmLogger.Error(err, "Kubernetes error reading KeycloakRealm CR.")
		return reconcile.Result{}, err
	}

	if instance.Spec.Unmanaged {
		realmLogger.Info("KeycloakRealm is Unmanaged.")
		// This will still be requeued if manageSuccess function returns non-nil error
		err := r.manageSuccess(instance, realmLogger, instance.DeletionTimestamp != nil)
		if err != nil {
			realmLogger.Error(err, "Error in KeycloakRealm success handler. Realm will be requeued.")
		}
		return reconcile.Result{Requeue: false}, err
	}

	// If no selector is set we can't figure out which Keycloak instance this realm should
	// be added to. Skip reconcile until a selector has been set.
	if instance.Spec.InstanceSelector == nil {
		realmLogger.Info(fmt.Sprintf("realm %v/%v has no instance selector and will be ignored", instance.Namespace, instance.Name))
		return reconcile.Result{Requeue: false}, nil
	}

	keycloaks, err := common.GetMatchingKeycloaks(r.context, r.client, instance.Spec.InstanceSelector)
	if err != nil {
		return r.ManageError(instance, realmLogger, err)
	}

	realmLogger.Info(fmt.Sprintf("Found %v matching keycloak(s) for realm %v/%v", len(keycloaks.Items), instance.Namespace, instance.Name))
	
	if len(keycloaks.Items) > 1 {
		realmLogger.Info("Warning: More than 1 matching keycloak is not an expected Vibrent use case.")
	}
	
	if len(keycloaks.Items) == 0 {
		realmLogger.Info("No matching keycloak instance discovered. Will be requeued in 1 minute.")
		return reconcile.Result{
			RequeueAfter: RequeueDelayError,
			Requeue:      true,
		}, nil
	}

	// The realm may be applicable to multiple keycloak instances,
	// process all of them
	for _, keycloak := range keycloaks.Items {
		// Get an authenticated keycloak api client for the instance
		keycloakFactory := common.LocalConfigKeycloakFactory{}

		authenticated, err := keycloakFactory.AuthenticatedClient(keycloak, false)

		if err != nil {
			return r.ManageError(instance, realmLogger, err)
		}

		// Compute the current state of the realm
		realmState := common.NewRealmState(r.context, keycloak)

		realmLogger.Info(fmt.Sprintf("read state for keycloak %v/%v, realm %v/%v",
			keycloak.Namespace,
			keycloak.Name,
			instance.Namespace,
			instance.Spec.Realm.Realm))

		err = realmState.Read(instance, authenticated, r.client)
		if err != nil {
			return r.ManageError(instance, realmLogger, err)
		}

		// Figure out the actions to keep the realms up to date with
		// the desired state
		reconciler := NewKeycloakRealmReconciler(keycloak)
		desiredState := reconciler.Reconcile(realmState, instance)
		actionRunner := common.NewClusterAndKeycloakActionRunner(r.context, r.client, r.scheme, instance, authenticated)

		// Run all actions to keep the realms updated
		err = actionRunner.RunAll(desiredState)
		if err != nil {
			return r.ManageError(instance, realmLogger, err)
		}
	}

	err = r.manageSuccess(instance, realmLogger, instance.DeletionTimestamp != nil)
	if err != nil {
		realmLogger.Error(err, "Error in KeycloakRealm success handler. Realm will be requeued.")
	}
	return reconcile.Result{Requeue: false}, err
}

func (r *ReconcileKeycloakRealm) manageSuccess(realm *kc.KeycloakRealm, realmLogger logr.Logger, deleted bool) error {
	realm.Status.Ready = true
	realm.Status.Message = ""
	realm.Status.Phase = v1alpha1.PhaseReconciling

	realmLogger.Info(fmt.Sprintf("Pushing successful reconcile to CR. Id: %s", realm.Spec.Realm.ID))
	err := r.client.Status().Update(r.context, realm)
	if err != nil {
		realmLogger.Error(err, "unable to update status")
	}

	// Finalizer already set?
	finalizerExists := false
	for _, finalizer := range realm.Finalizers {
		if finalizer == RealmFinalizer {
			finalizerExists = true
			break
		}
	}

	// Resource created and finalizer exists: nothing to do
	if !deleted && finalizerExists {
		realmLogger.Info("Resource created and finalizer exists: nothing to do")
		return nil
	}

	// Resource created and finalizer does not exist: add finalizer
	if !deleted && !finalizerExists {
		realm.Finalizers = append(realm.Finalizers, RealmFinalizer)
		realmLogger.Info(fmt.Sprintf("added finalizer to keycloak realm %v/%v",
			realm.Namespace,
			realm.Spec.Realm.Realm))

		return r.client.Update(r.context, realm)
	}

	// Otherwise remove the finalizer
	newFinalizers := []string{}
	for _, finalizer := range realm.Finalizers {
		if finalizer == RealmFinalizer {
			realmLogger.Info(fmt.Sprintf("removed finalizer from keycloak realm %v/%v",
				realm.Namespace,
				realm.Spec.Realm.Realm))

			continue
		}
		newFinalizers = append(newFinalizers, finalizer)
	}

	realm.Finalizers = newFinalizers
	return r.client.Update(r.context, realm)
}

func (r *ReconcileKeycloakRealm) ManageError(realm *kc.KeycloakRealm, realmLogger logr.Logger, issue error) (reconcile.Result, error) {
	r.recorder.Event(realm, "Warning", "ProcessingError", issue.Error())

	realm.Status.Message = issue.Error()
	realm.Status.Ready = false
	realm.Status.Phase = v1alpha1.PhaseFailing

	realmLogger.Info(fmt.Sprintf("Pushing unsuccessful reconcile to CR. Will be requeued in 1 minute. Id: %s, Message: %s", realm.Spec.Realm.ID, realm.Status.Message))
	err := r.client.Status().Update(r.context, realm)
	if err != nil {
		realmLogger.Error(err, "unable to update status")
	}

	return reconcile.Result{
		RequeueAfter: RequeueDelayError,
		Requeue:      true,
	}, nil
}
