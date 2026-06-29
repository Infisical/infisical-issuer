package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	issuerapi "github.com/Infisical/infisical-issuer/api/v1alpha1"
	"github.com/Infisical/infisical-issuer/internal/auth"
	"github.com/Infisical/infisical-issuer/internal/cache"
	"github.com/Infisical/infisical-issuer/internal/issuer/signer"
	"github.com/Infisical/infisical-issuer/internal/issuer/util"
)

const (
	// defaultHealthCheckInterval is how often a Ready issuer re-verifies Infisical.
	// Kept infrequent since each check also looks up the application and profile.
	defaultHealthCheckInterval = 5 * time.Minute
)

var (
	errValidateSpec         = errors.New("invalid issuer configuration")
	errHealthCheckerBuilder = errors.New("failed to build the healthchecker")
	errHealthCheckerCheck   = errors.New("healthcheck failed")
)

type IssuerReconciler struct {
	client.Client
	Kind                 string
	Scheme               *runtime.Scheme
	HealthCheckerBuilder signer.HealthCheckerBuilder
	AuthResolver         *auth.Resolver
	// ClusterResourceNamespace is where a ClusterIssuer's credentials resolve;
	// ignored for the namespaced Issuer kind.
	ClusterResourceNamespace string
	recorder                 record.EventRecorder
}

// resourceNamespace is the namespace this issuer's credentials must resolve within:
// its own namespace for an Issuer, or ClusterResourceNamespace for a ClusterIssuer.
func (r *IssuerReconciler) resourceNamespace(issuerNamespace string) string {
	if r.Kind == "ClusterIssuer" {
		return r.ClusterResourceNamespace
	}
	return issuerNamespace
}

// +kubebuilder:rbac:groups=infisical-issuer.infisical.com,resources=issuers;clusterissuers,verbs=get;list;watch
// +kubebuilder:rbac:groups=infisical-issuer.infisical.com,resources=issuers/status;clusterissuers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

func (r *IssuerReconciler) newIssuer() (client.Object, error) {
	issuerGVK := issuerapi.GroupVersion.WithKind(r.Kind)
	ro, err := r.Scheme.New(issuerGVK)
	if err != nil {
		return nil, err
	}
	return ro.(client.Object), nil
}

func readyConditionReason(status metav1.ConditionStatus) string {
	switch status {
	case metav1.ConditionTrue:
		return "Checked"
	case metav1.ConditionFalse:
		return "Error"
	default:
		return "Pending"
	}
}

func (r *IssuerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, err error) {
	log := ctrl.LoggerFrom(ctx)

	issuer, err := r.newIssuer()
	if err != nil {
		log.Error(err, "Unrecognised issuer type")
		return ctrl.Result{}, nil
	}
	if err := r.Get(ctx, req.NamespacedName, issuer); err != nil {
		if err := client.IgnoreNotFound(err); err != nil {
			return ctrl.Result{}, fmt.Errorf("unexpected get error: %w", err)
		}
		log.Info("Not found. Ignoring.")
		return ctrl.Result{}, nil
	}

	issuerSpec, issuerStatus, err := util.GetSpecAndStatus(issuer)
	if err != nil {
		log.Error(err, "Unexpected error while getting issuer spec and status. Not retrying.")
		return ctrl.Result{}, nil
	}

	report := func(conditionStatus metav1.ConditionStatus, message string, err error) {
		eventType := corev1.EventTypeNormal
		if err != nil {
			log.Error(err, message)
			eventType = corev1.EventTypeWarning
			message = fmt.Sprintf("%s: %v", message, err)
		} else {
			log.Info(message)
		}
		r.recorder.Event(
			issuer,
			eventType,
			issuerapi.EventReasonIssuerReconciler,
			message,
		)
		util.SetReadyCondition(issuerStatus, issuer.GetGeneration(), conditionStatus, readyConditionReason(conditionStatus), message)
	}

	defer func() {
		if err != nil {
			report(metav1.ConditionFalse, "Temporary error. Retrying", err)
		}
		if updateErr := r.Status().Update(ctx, issuer); updateErr != nil {
			err = utilerrors.NewAggregate([]error{err, updateErr})
			result = ctrl.Result{}
		}
	}()

	if ready := util.GetReadyCondition(issuerStatus); ready == nil {
		report(metav1.ConditionUnknown, "First seen", nil)
		return ctrl.Result{}, nil
	}

	resourceNamespace := r.resourceNamespace(req.Namespace)

	// Validate the auth config before logging in so misconfiguration fails fast.
	if err := r.AuthResolver.Validate(ctx, issuerSpec, resourceNamespace); err != nil {
		return ctrl.Result{}, fmt.Errorf("%w: %w", errValidateSpec, err)
	}

	cacheKey := cache.ClientCacheKey{Name: req.Name, Namespace: req.Namespace, Generation: issuer.GetGeneration()}
	checker, err := r.HealthCheckerBuilder(r.Client, r.AuthResolver, issuerSpec, cacheKey, resourceNamespace)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("%w: %w", errHealthCheckerBuilder, err)
	}

	if err := checker.Check(ctx); err != nil {
		return ctrl.Result{}, fmt.Errorf("%w: %w", errHealthCheckerCheck, err)
	}

	report(metav1.ConditionTrue, "Success", nil)
	return ctrl.Result{RequeueAfter: defaultHealthCheckInterval}, nil
}

func (r *IssuerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	issuerType, err := r.newIssuer()
	if err != nil {
		return err
	}
	r.recorder = mgr.GetEventRecorderFor(issuerapi.EventSource)
	return ctrl.NewControllerManagedBy(mgr).
		For(issuerType).
		Complete(r)
}
