package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	cmutil "github.com/cert-manager/cert-manager/pkg/api/util"

	issuerapi "github.com/Infisical/infisical-issuer/api/v1alpha1"
	"github.com/Infisical/infisical-issuer/internal/auth"
	"github.com/Infisical/infisical-issuer/internal/cache"
	"github.com/Infisical/infisical-issuer/internal/issuer/signer"
	issuerutil "github.com/Infisical/infisical-issuer/internal/issuer/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	errIssuerRef      = errors.New("error interpreting issuerRef")
	errGetIssuer      = errors.New("error getting issuer")
	errIssuerNotReady = errors.New("issuer is not ready")
	errSignerBuilder  = errors.New("failed to build the signer")
	errSignerSign     = errors.New("failed to sign")
)

const (
	// requestIDAnnotation holds the in-flight Infisical request id so an async
	// issuance is polled instead of re-created.
	requestIDAnnotation = "infisical-issuer.infisical.com/certificate-request-id"

	pendingRequeueInterval = 30 * time.Second
)

type CertificateRequestReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	SignerBuilder signer.Builder
	AuthResolver  *auth.Resolver

	// ClusterResourceNamespace is where a ClusterIssuer's credentials resolve;
	// ignored for the namespaced Issuer kind.
	ClusterResourceNamespace string

	Clock                  clock.Clock
	CheckApprovedCondition bool
	recorder               record.EventRecorder
}

// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
// +kubebuilder:rbac:groups="",resources=serviceaccounts/token,verbs=create

func (r *CertificateRequestReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, err error) {
	log := ctrl.LoggerFrom(ctx)

	var certificateRequest cmapi.CertificateRequest
	if err := r.Get(ctx, req.NamespacedName, &certificateRequest); err != nil {
		if err := client.IgnoreNotFound(err); err != nil {
			return ctrl.Result{}, fmt.Errorf("unexpected get error: %w", err)
		}
		log.Info("Not found. Ignoring.")
		return ctrl.Result{}, nil
	}

	if certificateRequest.Spec.IssuerRef.Group != issuerapi.GroupVersion.Group {
		log.Info("Foreign group. Ignoring.", "group", certificateRequest.Spec.IssuerRef.Group, "expectedGroup", issuerapi.GroupVersion.Group)
		return ctrl.Result{}, nil
	}

	if msg, ok := alreadyResolved(&certificateRequest); ok {
		log.Info(msg)
		return ctrl.Result{}, nil
	}

	// A denied CertificateRequest is terminal. Handle it before the approval
	// gate below, otherwise a denial would be ignored as merely "not approved".
	if cmutil.CertificateRequestIsDenied(&certificateRequest) {
		log.Info("CertificateRequest has been denied. Marking as failed.")
		if certificateRequest.Status.FailureTime == nil {
			nowTime := metav1.NewTime(r.Clock.Now())
			certificateRequest.Status.FailureTime = &nowTime
		}
		message := "The CertificateRequest was denied by an approval controller"
		r.recorder.Event(&certificateRequest, corev1.EventTypeNormal, issuerapi.EventReasonCertificateRequestReconciler, message)
		cmutil.SetCertificateRequestCondition(&certificateRequest, cmapi.CertificateRequestConditionReady, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonDenied, message)
		return ctrl.Result{}, r.Status().Update(ctx, &certificateRequest)
	}

	if r.CheckApprovedCondition && !cmutil.CertificateRequestIsApproved(&certificateRequest) {
		log.Info("CertificateRequest has not been approved yet. Ignoring.")
		return ctrl.Result{}, nil
	}

	report := func(reason, message string, err error) {
		status := cmmeta.ConditionFalse
		if reason == cmapi.CertificateRequestReasonIssued {
			status = cmmeta.ConditionTrue
		}
		eventType := corev1.EventTypeNormal
		if err != nil {
			log.Error(err, message)
			eventType = corev1.EventTypeWarning
			message = fmt.Sprintf("%s: %v", message, err)
		} else {
			log.Info(message)
		}
		r.recorder.Event(
			&certificateRequest,
			eventType,
			issuerapi.EventReasonCertificateRequestReconciler,
			message,
		)
		cmutil.SetCertificateRequestCondition(
			&certificateRequest,
			cmapi.CertificateRequestConditionReady,
			status,
			reason,
			message,
		)
	}

	defer func() {
		if err != nil {
			report(cmapi.CertificateRequestReasonPending, "Temporary error. Retrying", err)
		}
		if updateErr := r.Status().Update(ctx, &certificateRequest); updateErr != nil {
			err = utilerrors.NewAggregate([]error{err, updateErr})
			result = ctrl.Result{}
		}
	}()

	if ready := cmutil.GetCertificateRequestCondition(&certificateRequest, cmapi.CertificateRequestConditionReady); ready == nil {
		report(cmapi.CertificateRequestReasonPending, "Initialising Ready condition", nil)
		return ctrl.Result{}, nil
	}

	issuerGVK := issuerapi.GroupVersion.WithKind(certificateRequest.Spec.IssuerRef.Kind)
	issuerRO, err := r.Scheme.New(issuerGVK)
	if err != nil {
		report(cmapi.CertificateRequestReasonFailed, "Unrecognised kind. Ignoring", fmt.Errorf("%w: %w", errIssuerRef, err))
		return ctrl.Result{}, nil
	}
	issuer := issuerRO.(client.Object)
	// Create a Namespaced name for Issuer and a non-Namespaced name for ClusterIssuer
	issuerName := types.NamespacedName{
		Name: certificateRequest.Spec.IssuerRef.Name,
	}
	// resourceNamespace is where the issuer's credentials resolve: the request's
	// namespace for an Issuer, or ClusterResourceNamespace for a ClusterIssuer.
	var resourceNamespace string
	switch t := issuer.(type) {
	case *issuerapi.Issuer:
		issuerName.Namespace = certificateRequest.Namespace
		resourceNamespace = certificateRequest.Namespace
		log = log.WithValues("issuer", issuerName)
	case *issuerapi.ClusterIssuer:
		resourceNamespace = r.ClusterResourceNamespace
		log = log.WithValues("clusterissuer", issuerName)
	default:
		report(cmapi.CertificateRequestReasonFailed, "The issuerRef referred to a registered Kind which is not yet handled. Ignoring", fmt.Errorf("unexpected issuer type: %v", t))
		return ctrl.Result{}, nil
	}

	if err := r.Get(ctx, issuerName, issuer); err != nil {
		return ctrl.Result{}, fmt.Errorf("%w: %w", errGetIssuer, err)
	}

	issuerSpec, issuerStatus, err := issuerutil.GetSpecAndStatus(issuer)

	if err != nil {
		report(cmapi.CertificateRequestReasonFailed, "Unable to get the IssuerStatus. Ignoring", err)
		return ctrl.Result{}, nil
	}

	if !issuerutil.IsReady(issuerStatus) {
		return ctrl.Result{}, errIssuerNotReady
	}

	cacheKey := cache.ClientCacheKey{Name: issuerName.Name, Namespace: issuerName.Namespace, Generation: issuer.GetGeneration()}
	signerObj, err := r.SignerBuilder(r.Client, r.AuthResolver, issuerSpec, cacheKey, resourceNamespace)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("%w: %w", errSignerBuilder, err)
	}

	priorRequestID := certificateRequest.Annotations[requestIDAnnotation]
	signResult, err := signerObj.Sign(ctx, certificateRequest, priorRequestID)
	if err != nil {
		// A terminal failure (policy violation, rejected approval) will never
		// succeed on retry, so fail the request instead of requeuing forever.
		if signer.IsTerminal(err) {
			if certificateRequest.Status.FailureTime == nil {
				nowTime := metav1.NewTime(r.Clock.Now())
				certificateRequest.Status.FailureTime = &nowTime
			}
			report(cmapi.CertificateRequestReasonFailed, "Infisical could not issue the certificate", err)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("%w: %w", errSignerSign, err)
	}

	if signResult.Pending {
		// Record the in-flight request id so the next reconcile polls it instead of
		// creating a duplicate. A merge Patch (no resourceVersion precondition) avoids
		// failing on concurrent status churn; a duplicate is still possible if the pod
		// dies between create and patch, leaving a pending request an operator can deny.
		if signResult.RequestID != "" && certificateRequest.Annotations[requestIDAnnotation] != signResult.RequestID {
			base := certificateRequest.DeepCopy()
			if certificateRequest.Annotations == nil {
				certificateRequest.Annotations = map[string]string{}
			}
			certificateRequest.Annotations[requestIDAnnotation] = signResult.RequestID
			if err := r.Patch(ctx, &certificateRequest, client.MergeFrom(base)); err != nil {
				return ctrl.Result{}, fmt.Errorf("recording certificate request id: %w", err)
			}
		}
		report(cmapi.CertificateRequestReasonPending, signResult.PendingMessage, nil)
		return ctrl.Result{RequeueAfter: pendingRequeueInterval}, nil
	}

	certificateRequest.Status.Certificate = signResult.Certificate
	certificateRequest.Status.CA = signResult.CA

	report(cmapi.CertificateRequestReasonIssued, "Signed", nil)
	return ctrl.Result{}, nil
}

func alreadyResolved(cr *cmapi.CertificateRequest) (string, bool) {
	switch {
	case cmutil.CertificateRequestHasCondition(cr, cmapi.CertificateRequestCondition{
		Type:   cmapi.CertificateRequestConditionReady,
		Status: cmmeta.ConditionTrue,
	}):
		return "CertificateRequest is Ready. Ignoring.", true
	case cmutil.CertificateRequestHasCondition(cr, cmapi.CertificateRequestCondition{
		Type:   cmapi.CertificateRequestConditionReady,
		Status: cmmeta.ConditionFalse,
		Reason: cmapi.CertificateRequestReasonFailed,
	}):
		return "CertificateRequest is Failed. Ignoring.", true
	case cmutil.CertificateRequestHasCondition(cr, cmapi.CertificateRequestCondition{
		Type:   cmapi.CertificateRequestConditionReady,
		Status: cmmeta.ConditionFalse,
		Reason: cmapi.CertificateRequestReasonDenied,
	}):
		return "CertificateRequest already has a Ready condition with Denied Reason. Ignoring.", true
	}
	return "", false
}

func (r *CertificateRequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.recorder = mgr.GetEventRecorderFor(issuerapi.EventSource)
	return ctrl.NewControllerManagedBy(mgr).
		For(&cmapi.CertificateRequest{}).
		Complete(r)
}
