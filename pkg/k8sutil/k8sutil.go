package k8sutil

import (
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"

	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

var log = logf.Log.WithName("k8sutil")

// GetWatchNamespace returns the Namespace the operator should be watching for changes
func GetWatchNamespace() (string, error) {
	// WatchNamespaceEnvVar is the constant for env variable WATCH_NAMESPACE
	// which specifies the Namespace to watch.
	// An empty value means the operator is running with cluster scope.
	var watchNamespaceEnvVar = "WATCH_NAMESPACE"

	ns, found := os.LookupEnv(watchNamespaceEnvVar)
	if !found {
		return "", ErrWatchNamespaceEnvVar
	}

	log.Info(fmt.Sprintf("WATCH_NAMESPACE: %s", ns))
	return ns, nil
}

// ErrNoNamespace indicates that a namespace could not be found for the current
// environment
var ErrNoNamespace = fmt.Errorf("namespace not found for current environment")

// ErrRunLocal indicates that the operator is set to run in local mode (this error
// is returned by functions that only work on operators running in cluster mode)
var ErrRunLocal = fmt.Errorf("operator run mode forced to local")

// ErrWatchNamespaceEnvVar indicates that the namespace environment variable is not set
var ErrWatchNamespaceEnvVar = fmt.Errorf("watch namespace env var must be set")

// GetSyncPeriod returns a time based on env variable SYNC_PERIOD, or 5 minutes if unset or empty_string
func GetSyncPeriod() (time.Duration, error) {
	var syncPeriodEnvVar = "SYNC_PERIOD"

	sp, found := os.LookupEnv(syncPeriodEnvVar)
	if !found || sp == "" {
		log.Info("SYNC_PERIOD unset or empty. Default is 5m.")
		return time.Minute * 5, nil
	}

	log.Info(fmt.Sprintf("SYNC_PERIOD value read from ENV: %s", sp))
	return time.ParseDuration(sp)
}

// GetClientMaxConcurrentReconciles returns a time based on env variable CLIENT_MAX_CONCURRENT_RECONCILES, or 5 minutes if unset or empty_string
func GetClientMaxConcurrentReconciles() (int, error) {
	var mcrEnvVar = "CLIENT_MAX_CONCURRENT_RECONCILES"

	env, found := os.LookupEnv(mcrEnvVar)
	if !found || env == "" {
		log.Info("CLIENT_MAX_CONCURRENT_RECONCILES unset or empty. Default is 1.")
		return 1, nil
	}

	log.Info(fmt.Sprintf("CLIENT_MAX_CONCURRENT_RECONCILES value read from ENV: %s", env))
	return strconv.Atoi(env)
}

// GetRealmMaxConcurrentReconciles returns a time based on env variable REALM_MAX_CONCURRENT_RECONCILES, or 5 minutes if unset or empty_string
func GetRealmMaxConcurrentReconciles() (int, error) {
	var mcrEnvVar = "REALM_MAX_CONCURRENT_RECONCILES"

	env, found := os.LookupEnv(mcrEnvVar)
	if !found || env == "" {
		log.Info("REALM_MAX_CONCURRENT_RECONCILES unset or empty. Default is 1.")
		return 1, nil
	}

	log.Info(fmt.Sprintf("REALM_MAX_CONCURRENT_RECONCILES value read from ENV: %s", env))
	return strconv.Atoi(env)
}

// GetOperatorNamespace returns the namespace the operator should be running in.
func GetOperatorNamespace() (string, error) {
	if isRunModeLocal() {
		return "", ErrRunLocal
	}
	nsBytes, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err != nil {
		if os.IsNotExist(err) {
			return "", ErrNoNamespace
		}
		return "", err
	}
	ns := strings.TrimSpace(string(nsBytes))
	return ns, nil
}

// GetGVKsFromAddToScheme takes in the runtime scheme and filters out all generic apimachinery meta types.
// It returns just the GVK specific to this scheme.
func GetGVKsFromAddToScheme(addToSchemeFunc func(*runtime.Scheme) error) ([]schema.GroupVersionKind, error) {
	s := runtime.NewScheme()
	err := addToSchemeFunc(s)
	if err != nil {
		return nil, err
	}
	schemeAllKnownTypes := s.AllKnownTypes()
	ownGVKs := []schema.GroupVersionKind{}
	for gvk := range schemeAllKnownTypes {
		if !isKubeMetaKind(gvk.Kind) {
			ownGVKs = append(ownGVKs, gvk)
		}
	}

	return ownGVKs, nil
}

func isRunModeLocal() bool {
	return !isRunModeCluster()
}

// IsRunInCluster checks if the operator is run in cluster
func isRunModeCluster() bool {
	_, err := os.Stat("/var/run/secrets/kubernetes.io/serviceaccount")
	if err == nil {
		return true
	}

	return !os.IsNotExist(err)
}

func isKubeMetaKind(kind string) bool {
	if strings.HasSuffix(kind, "List") ||
		kind == "PatchOptions" ||
		kind == "GetOptions" ||
		kind == "DeleteOptions" ||
		kind == "ExportOptions" ||
		kind == "APIVersions" ||
		kind == "APIGroupList" ||
		kind == "APIResourceList" ||
		kind == "UpdateOptions" ||
		kind == "CreateOptions" ||
		kind == "Status" ||
		kind == "WatchEvent" ||
		kind == "ListOptions" ||
		kind == "APIGroup" {
		return true
	}

	return false
}

// ResourceExists returns true if the given resource kind exists
// in the given api groupversion
func ResourceExists(dc discovery.DiscoveryInterface, apiGroupVersion, kind string) (bool, error) {
	_, apiLists, err := dc.ServerGroupsAndResources()
	if err != nil {
		return false, err
	}
	for _, apiList := range apiLists {
		if apiList.GroupVersion == apiGroupVersion {
			for _, r := range apiList.APIResources {
				if r.Kind == kind {
					return true, nil
				}
			}
		}
	}
	return false, nil
}
