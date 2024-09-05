/*
Copyright 2024 Infisical.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sampleissuerapi "github.com/Infisical/infisical-issuer/api/v1alpha1"
	"github.com/Infisical/infisical-issuer/internal/issuer/signer"
	"github.com/Infisical/infisical-issuer/internal/issuer/util"
)

const (
	defaultHealthCheckInterval = time.Minute
)

var (
	errGetAuthSecret        = errors.New("failed to get Secret containing Issuer credentials")
	errHealthCheckerBuilder = errors.New("failed to build the healthchecker")
	errHealthCheckerCheck   = errors.New("healthcheck failed")
)

// IssuerReconciler reconciles a Issuer object
type IssuerReconciler struct {
	client.Client
	Kind                     string
	Scheme                   *runtime.Scheme
	ClusterResourceNamespace string
	HealthCheckerBuilder     signer.HealthCheckerBuilder
	recorder                 record.EventRecorder
}

// +kubebuilder:rbac:groups=infisical-issuer.infisical.com,resources=issuers;clusterissuers,verbs=get;list;watch
// +kubebuilder:rbac:groups=infisical-issuer.infisical.com,resources=issuers/status;clusterissuers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

func (r *IssuerReconciler) newIssuer() (client.Object, error) {
	issuerGVK := sampleissuerapi.GroupVersion.WithKind(r.Kind)
	ro, err := r.Scheme.New(issuerGVK)
	if err != nil {
		return nil, err
	}
	return ro.(client.Object), nil
}

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the Issuer object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.19.0/pkg/reconcile
func (r *IssuerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, err error) {
	fmt.Println("Inside IssuerReconciler")
	log := ctrl.LoggerFrom(ctx)

	issuer, err := r.newIssuer()
	if err != nil {
		log.Error(err, "Unrecognised issuer type")
		return ctrl.Result{}, nil
	}
	if err := r.Get(ctx, req.NamespacedName, issuer); err != nil {
		if err := client.IgnoreNotFound(err); err != nil {
			return ctrl.Result{}, fmt.Errorf("unexpected get error: %v", err)
		}
		log.Info("Not found. Ignoring.")
		return ctrl.Result{}, nil
	}

	issuerSpec, issuerStatus, err := util.GetSpecAndStatus(issuer)
	if err != nil {
		log.Error(err, "Unexpected error while getting issuer spec and status. Not retrying.")
		return ctrl.Result{}, nil
	}

	// report gives feedback by updating the Ready Condition of the {Cluster}Issuer
	// For added visibility we also log a message and create a Kubernetes Event.
	report := func(conditionStatus sampleissuerapi.ConditionStatus, message string, err error) {
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
			sampleissuerapi.EventReasonIssuerReconciler,
			message,
		)
		util.SetReadyCondition(issuerStatus, conditionStatus, sampleissuerapi.EventReasonIssuerReconciler, message)
	}

	// Always attempt to update the Ready condition
	defer func() {
		if err != nil {
			report(sampleissuerapi.ConditionFalse, "Temporary error. Retrying", err)
		}
		if updateErr := r.Status().Update(ctx, issuer); updateErr != nil {
			err = utilerrors.NewAggregate([]error{err, updateErr})
			result = ctrl.Result{}
		}
	}()

	if ready := util.GetReadyCondition(issuerStatus); ready == nil {
		report(sampleissuerapi.ConditionUnknown, "First seen", nil)
		return ctrl.Result{}, nil
	}

	secretName := types.NamespacedName{
		Name: issuerSpec.AuthSecretName,
	}

	switch issuer.(type) {
	case *sampleissuerapi.Issuer:
		secretName.Namespace = req.Namespace
	case *sampleissuerapi.ClusterIssuer:
		secretName.Namespace = r.ClusterResourceNamespace
	default:
		log.Error(fmt.Errorf("unexpected issuer type: %t", issuer), "Not retrying.")
		return ctrl.Result{}, nil
	}

	var secret corev1.Secret
	if err := r.Get(ctx, secretName, &secret); err != nil {
		return ctrl.Result{}, fmt.Errorf("%w, secret name: %s, reason: %v", errGetAuthSecret, secretName, err)
	}

	checker, err := r.HealthCheckerBuilder(issuerSpec, secret.Data) // NOTE (dangtony98): Consider removing health check for now
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("%w: %v", errHealthCheckerBuilder, err)
	}

	if err := checker.Check(); err != nil {
		return ctrl.Result{}, fmt.Errorf("%w: %v", errHealthCheckerCheck, err)
	}

	report(sampleissuerapi.ConditionTrue, "Success", nil)
	return ctrl.Result{RequeueAfter: defaultHealthCheckInterval}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *IssuerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	issuerType, err := r.newIssuer()
	if err != nil {
		return err
	}
	r.recorder = mgr.GetEventRecorderFor(sampleissuerapi.EventSource)
	return ctrl.NewControllerManagedBy(mgr).
		For(issuerType). // NOTE(dangtony98): This is the type of the issuer
		Complete(r)
}
