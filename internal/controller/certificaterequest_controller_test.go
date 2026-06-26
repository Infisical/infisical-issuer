package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	cmutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	cmgen "github.com/cert-manager/cert-manager/test/unit/gen"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	clock "k8s.io/utils/clock/testing"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	issuerapi "github.com/Infisical/infisical-issuer/api/v1alpha1"
	"github.com/Infisical/infisical-issuer/internal/auth"
	"github.com/Infisical/infisical-issuer/internal/cache"
	"github.com/Infisical/infisical-issuer/internal/issuer/signer"
)

var (
	fixedClockStart = time.Date(2021, time.January, 1, 1, 0, 0, 0, time.UTC)
	fixedClock      = clock.NewFakeClock(fixedClockStart)
)

type fakeSigner struct {
	result  signer.SignResult
	errSign error
}

func (o *fakeSigner) Sign(_ context.Context, _ cmapi.CertificateRequest, _ string) (signer.SignResult, error) {
	return o.result, o.errSign
}

// readyIssuerStatus is the status shared by issuers that should be treated as Ready.
func readyIssuerStatus() issuerapi.IssuerStatus {
	return issuerapi.IssuerStatus{
		Conditions: []metav1.Condition{
			{Type: issuerapi.ConditionReady, Status: metav1.ConditionTrue, Reason: "Ok", Message: "ready"},
		},
	}
}

func issuedSigner() signer.Builder {
	return func(client.Client, *auth.Resolver, *issuerapi.IssuerSpec, cache.ClientCacheKey, string) (signer.Signer, error) {
		return &fakeSigner{result: signer.SignResult{
			Certificate: []byte("fake signed certificate"),
			CA:          []byte("fake signed certificate"),
		}}, nil
	}
}

func pendingSigner(requestID, message string) signer.Builder {
	return func(client.Client, *auth.Resolver, *issuerapi.IssuerSpec, cache.ClientCacheKey, string) (signer.Signer, error) {
		return &fakeSigner{result: signer.SignResult{Pending: true, RequestID: requestID, PendingMessage: message}}, nil
	}
}

func terminalSigner(message string) signer.Builder {
	return func(client.Client, *auth.Resolver, *issuerapi.IssuerSpec, cache.ClientCacheKey, string) (signer.Signer, error) {
		return &fakeSigner{errSign: signer.NewTerminalErrorForTesting(message)}, nil
	}
}

type certificateRequestTestCase struct {
	name                         types.NamespacedName
	issuerObjects                []client.Object
	crObjects                    []client.Object
	signerBuilder                signer.Builder
	expectedResult               ctrl.Result
	expectedError                error
	expectedReadyConditionStatus cmmeta.ConditionStatus
	expectedReadyConditionReason string
	expectedFailureTime          *metav1.Time
	expectedCertificate          []byte
}

var _ = Describe("CertificateRequest Controller", func() {
	nowMetaTime := metav1.NewTime(fixedClockStart)

	tests := map[string]certificateRequestTestCase{
		"success-issuer": {
			name: types.NamespacedName{Namespace: "ns1", Name: "cr1"},
			crObjects: []client.Object{
				cmgen.CertificateRequest(
					"cr1",
					cmgen.SetCertificateRequestNamespace("ns1"),
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  "issuer1",
						Group: issuerapi.GroupVersion.Group,
						Kind:  "Issuer",
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionApproved,
						Status: cmmeta.ConditionTrue,
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionReady,
						Status: cmmeta.ConditionUnknown,
					}),
				),
			},
			issuerObjects: []client.Object{&issuerapi.Issuer{
				ObjectMeta: metav1.ObjectMeta{Name: "issuer1", Namespace: "ns1"},
				Status:     readyIssuerStatus(),
			}},
			signerBuilder:                issuedSigner(),
			expectedReadyConditionStatus: cmmeta.ConditionTrue,
			expectedReadyConditionReason: cmapi.CertificateRequestReasonIssued,
			expectedFailureTime:          nil,
			expectedCertificate:          []byte("fake signed certificate"),
		},
		"success-cluster-issuer": {
			name: types.NamespacedName{Namespace: "ns1", Name: "cr1"},
			crObjects: []client.Object{
				cmgen.CertificateRequest(
					"cr1",
					cmgen.SetCertificateRequestNamespace("ns1"),
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  "clusterissuer1",
						Group: issuerapi.GroupVersion.Group,
						Kind:  "ClusterIssuer",
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionApproved,
						Status: cmmeta.ConditionTrue,
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionReady,
						Status: cmmeta.ConditionUnknown,
					}),
				),
			},
			issuerObjects: []client.Object{&issuerapi.ClusterIssuer{
				ObjectMeta: metav1.ObjectMeta{Name: "clusterissuer1"},
				Status:     readyIssuerStatus(),
			}},
			signerBuilder:                issuedSigner(),
			expectedReadyConditionStatus: cmmeta.ConditionTrue,
			expectedReadyConditionReason: cmapi.CertificateRequestReasonIssued,
			expectedFailureTime:          nil,
			expectedCertificate:          []byte("fake signed certificate"),
		},
		"certificaterequest-not-found": {
			name: types.NamespacedName{Namespace: "ns1", Name: "cr1"},
		},
		"issuer-ref-foreign-group": {
			name: types.NamespacedName{Namespace: "ns1", Name: "cr1"},
			crObjects: []client.Object{
				cmgen.CertificateRequest(
					"cr1",
					cmgen.SetCertificateRequestNamespace("ns1"),
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  "issuer1",
						Group: "foreign-issuer.example.com",
					}),
				),
			},
		},
		"certificaterequest-already-ready": {
			name: types.NamespacedName{Namespace: "ns1", Name: "cr1"},
			crObjects: []client.Object{
				cmgen.CertificateRequest(
					"cr1",
					cmgen.SetCertificateRequestNamespace("ns1"),
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  "issuer1",
						Group: issuerapi.GroupVersion.Group,
						Kind:  "Issuer",
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionApproved,
						Status: cmmeta.ConditionTrue,
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionReady,
						Status: cmmeta.ConditionTrue,
					}),
				),
			},
		},
		"certificaterequest-missing-ready-condition": {
			name: types.NamespacedName{Namespace: "ns1", Name: "cr1"},
			crObjects: []client.Object{
				cmgen.CertificateRequest(
					"cr1",
					cmgen.SetCertificateRequestNamespace("ns1"),
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  "issuer1",
						Group: issuerapi.GroupVersion.Group,
						Kind:  "Issuer",
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionApproved,
						Status: cmmeta.ConditionTrue,
					}),
				),
			},
			expectedReadyConditionStatus: cmmeta.ConditionFalse,
			expectedReadyConditionReason: cmapi.CertificateRequestReasonPending,
		},
		"issuer-ref-unknown-kind": {
			name: types.NamespacedName{Namespace: "ns1", Name: "cr1"},
			crObjects: []client.Object{
				cmgen.CertificateRequest(
					"cr1",
					cmgen.SetCertificateRequestNamespace("ns1"),
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  "issuer1",
						Group: issuerapi.GroupVersion.Group,
						Kind:  "ForeignKind",
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionApproved,
						Status: cmmeta.ConditionTrue,
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionReady,
						Status: cmmeta.ConditionUnknown,
					}),
				),
			},
			expectedReadyConditionStatus: cmmeta.ConditionFalse,
			expectedReadyConditionReason: cmapi.CertificateRequestReasonFailed,
		},
		"issuer-not-found": {
			name: types.NamespacedName{Namespace: "ns1", Name: "cr1"},
			crObjects: []client.Object{
				cmgen.CertificateRequest(
					"cr1",
					cmgen.SetCertificateRequestNamespace("ns1"),
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  "issuer1",
						Group: issuerapi.GroupVersion.Group,
						Kind:  "Issuer",
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionApproved,
						Status: cmmeta.ConditionTrue,
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionReady,
						Status: cmmeta.ConditionUnknown,
					}),
				),
			},
			issuerObjects:                []client.Object{},
			expectedError:                errGetIssuer,
			expectedReadyConditionStatus: cmmeta.ConditionFalse,
			expectedReadyConditionReason: cmapi.CertificateRequestReasonPending,
		},
		"clusterissuer-not-found": {
			name: types.NamespacedName{Namespace: "ns1", Name: "cr1"},
			crObjects: []client.Object{
				cmgen.CertificateRequest(
					"cr1",
					cmgen.SetCertificateRequestNamespace("ns1"),
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  "clusterissuer1",
						Group: issuerapi.GroupVersion.Group,
						Kind:  "ClusterIssuer",
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionApproved,
						Status: cmmeta.ConditionTrue,
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionReady,
						Status: cmmeta.ConditionUnknown,
					}),
				),
			},
			expectedError:                errGetIssuer,
			expectedReadyConditionStatus: cmmeta.ConditionFalse,
			expectedReadyConditionReason: cmapi.CertificateRequestReasonPending,
		},
		"issuer-not-ready": {
			name: types.NamespacedName{Namespace: "ns1", Name: "cr1"},
			crObjects: []client.Object{
				cmgen.CertificateRequest(
					"cr1",
					cmgen.SetCertificateRequestNamespace("ns1"),
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  "issuer1",
						Group: issuerapi.GroupVersion.Group,
						Kind:  "Issuer",
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionApproved,
						Status: cmmeta.ConditionTrue,
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionReady,
						Status: cmmeta.ConditionUnknown,
					}),
				),
			},
			issuerObjects: []client.Object{&issuerapi.Issuer{
				ObjectMeta: metav1.ObjectMeta{Name: "issuer1", Namespace: "ns1"},
				Status: issuerapi.IssuerStatus{
					Conditions: []metav1.Condition{
						{Type: issuerapi.ConditionReady, Status: metav1.ConditionFalse, Reason: "NotReady", Message: "not ready"},
					},
				},
			}},
			expectedError:                errIssuerNotReady,
			expectedReadyConditionStatus: cmmeta.ConditionFalse,
			expectedReadyConditionReason: cmapi.CertificateRequestReasonPending,
		},
		"signer-builder-error": {
			name: types.NamespacedName{Namespace: "ns1", Name: "cr1"},
			crObjects: []client.Object{
				cmgen.CertificateRequest(
					"cr1",
					cmgen.SetCertificateRequestNamespace("ns1"),
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  "issuer1",
						Group: issuerapi.GroupVersion.Group,
						Kind:  "Issuer",
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionApproved,
						Status: cmmeta.ConditionTrue,
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionReady,
						Status: cmmeta.ConditionUnknown,
					}),
				),
			},
			issuerObjects: []client.Object{&issuerapi.Issuer{
				ObjectMeta: metav1.ObjectMeta{Name: "issuer1", Namespace: "ns1"},
				Status:     readyIssuerStatus(),
			}},
			signerBuilder: func(client.Client, *auth.Resolver, *issuerapi.IssuerSpec, cache.ClientCacheKey, string) (signer.Signer, error) {
				return nil, errors.New("simulated signer builder error")
			},
			expectedError:                errSignerBuilder,
			expectedReadyConditionStatus: cmmeta.ConditionFalse,
			expectedReadyConditionReason: cmapi.CertificateRequestReasonPending,
		},
		"signer-error": {
			name: types.NamespacedName{Namespace: "ns1", Name: "cr1"},
			crObjects: []client.Object{
				cmgen.CertificateRequest(
					"cr1",
					cmgen.SetCertificateRequestNamespace("ns1"),
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  "issuer1",
						Group: issuerapi.GroupVersion.Group,
						Kind:  "Issuer",
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionApproved,
						Status: cmmeta.ConditionTrue,
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionReady,
						Status: cmmeta.ConditionUnknown,
					}),
				),
			},
			issuerObjects: []client.Object{&issuerapi.Issuer{
				ObjectMeta: metav1.ObjectMeta{Name: "issuer1", Namespace: "ns1"},
				Status:     readyIssuerStatus(),
			}},
			signerBuilder: func(client.Client, *auth.Resolver, *issuerapi.IssuerSpec, cache.ClientCacheKey, string) (signer.Signer, error) {
				return &fakeSigner{errSign: errors.New("simulated sign error")}, nil
			},
			expectedError:                errSignerSign,
			expectedReadyConditionStatus: cmmeta.ConditionFalse,
			expectedReadyConditionReason: cmapi.CertificateRequestReasonPending,
		},
		"request-not-approved": {
			name: types.NamespacedName{Namespace: "ns1", Name: "cr1"},
			crObjects: []client.Object{
				cmgen.CertificateRequest(
					"cr1",
					cmgen.SetCertificateRequestNamespace("ns1"),
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  "issuer1",
						Group: issuerapi.GroupVersion.Group,
						Kind:  "Issuer",
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionReady,
						Status: cmmeta.ConditionUnknown,
					}),
				),
			},
			issuerObjects: []client.Object{&issuerapi.Issuer{
				ObjectMeta: metav1.ObjectMeta{Name: "issuer1", Namespace: "ns1"},
				Status:     readyIssuerStatus(),
			}},
			signerBuilder:       issuedSigner(),
			expectedFailureTime: nil,
			expectedCertificate: nil,
		},
		"request-denied": {
			name: types.NamespacedName{Namespace: "ns1", Name: "cr1"},
			crObjects: []client.Object{
				cmgen.CertificateRequest(
					"cr1",
					cmgen.SetCertificateRequestNamespace("ns1"),
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  "issuer1",
						Group: issuerapi.GroupVersion.Group,
						Kind:  "Issuer",
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionDenied,
						Status: cmmeta.ConditionTrue,
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionReady,
						Status: cmmeta.ConditionUnknown,
					}),
				),
			},
			issuerObjects: []client.Object{&issuerapi.Issuer{
				ObjectMeta: metav1.ObjectMeta{Name: "issuer1", Namespace: "ns1"},
				Status:     readyIssuerStatus(),
			}},
			signerBuilder:                issuedSigner(),
			expectedCertificate:          nil,
			expectedFailureTime:          &nowMetaTime,
			expectedReadyConditionStatus: cmmeta.ConditionFalse,
			expectedReadyConditionReason: cmapi.CertificateRequestReasonDenied,
		},
		"signer-pending": {
			name: types.NamespacedName{Namespace: "ns1", Name: "cr1"},
			crObjects: []client.Object{
				cmgen.CertificateRequest(
					"cr1",
					cmgen.SetCertificateRequestNamespace("ns1"),
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  "issuer1",
						Group: issuerapi.GroupVersion.Group,
						Kind:  "Issuer",
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionApproved,
						Status: cmmeta.ConditionTrue,
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionReady,
						Status: cmmeta.ConditionUnknown,
					}),
				),
			},
			issuerObjects: []client.Object{&issuerapi.Issuer{
				ObjectMeta: metav1.ObjectMeta{Name: "issuer1", Namespace: "ns1"},
				Status:     readyIssuerStatus(),
			}},
			signerBuilder:                pendingSigner("req-abc", "awaiting issuance"),
			expectedResult:               ctrl.Result{RequeueAfter: pendingRequeueInterval},
			expectedCertificate:          nil,
			expectedFailureTime:          nil,
			expectedReadyConditionStatus: cmmeta.ConditionFalse,
			expectedReadyConditionReason: cmapi.CertificateRequestReasonPending,
		},
		"signer-terminal-failure": {
			name: types.NamespacedName{Namespace: "ns1", Name: "cr1"},
			crObjects: []client.Object{
				cmgen.CertificateRequest(
					"cr1",
					cmgen.SetCertificateRequestNamespace("ns1"),
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  "issuer1",
						Group: issuerapi.GroupVersion.Group,
						Kind:  "Issuer",
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionApproved,
						Status: cmmeta.ConditionTrue,
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionReady,
						Status: cmmeta.ConditionUnknown,
					}),
				),
			},
			issuerObjects: []client.Object{&issuerapi.Issuer{
				ObjectMeta: metav1.ObjectMeta{Name: "issuer1", Namespace: "ns1"},
				Status:     readyIssuerStatus(),
			}},
			signerBuilder:                terminalSigner("policy violation"),
			expectedCertificate:          nil,
			expectedFailureTime:          &nowMetaTime,
			expectedReadyConditionStatus: cmmeta.ConditionFalse,
			expectedReadyConditionReason: cmapi.CertificateRequestReasonFailed,
		},
	}

	for name, tc := range tests {
		It(fmt.Sprintf("handles %s", name), func() {
			scheme := runtime.NewScheme()
			Expect(issuerapi.AddToScheme(scheme)).To(Succeed())
			Expect(cmapi.AddToScheme(scheme)).To(Succeed())
			Expect(corev1.AddToScheme(scheme)).To(Succeed())

			eventRecorder := record.NewFakeRecorder(100)
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tc.crObjects...).
				WithObjects(tc.issuerObjects...).
				WithStatusSubresource(tc.issuerObjects...).
				WithStatusSubresource(tc.crObjects...).
				Build()

			controller := CertificateRequestReconciler{
				Client:                 fakeClient,
				Scheme:                 scheme,
				SignerBuilder:          tc.signerBuilder,
				CheckApprovedCondition: true,
				Clock:                  fixedClock,
				recorder:               eventRecorder,
			}

			var crBefore cmapi.CertificateRequest
			if err := fakeClient.Get(context.TODO(), tc.name, &crBefore); err != nil {
				Expect(client.IgnoreNotFound(err)).NotTo(HaveOccurred(), "unexpected error from fake client")
			}

			result, reconcileErr := controller.Reconcile(
				ctrl.LoggerInto(context.TODO(), logr.Discard()),
				reconcile.Request{NamespacedName: tc.name},
			)

			var actualEvents []string
			drained := false
			for !drained {
				select {
				case e := <-eventRecorder.Events:
					actualEvents = append(actualEvents, e)
				default:
					drained = true
				}
			}

			if tc.expectedError != nil {
				Expect(reconcileErr).To(HaveOccurred())
				Expect(errors.Is(reconcileErr, tc.expectedError)).To(BeTrue(),
					"unexpected error type. expected: %v, got: %v", tc.expectedError, reconcileErr)
			} else {
				Expect(reconcileErr).NotTo(HaveOccurred())
			}

			Expect(result).To(Equal(tc.expectedResult), "Unexpected result")

			var crAfter cmapi.CertificateRequest
			if err := fakeClient.Get(context.TODO(), tc.name, &crAfter); err != nil {
				Expect(client.IgnoreNotFound(err)).NotTo(HaveOccurred(), "unexpected error from fake client")
				return
			}

			if crBefore.ResourceVersion == crAfter.ResourceVersion {
				Expect(actualEvents).To(BeEmpty(), "Events should only be created if the CertificateRequest is modified")
				return
			}

			Expect(crAfter.Status.Certificate).To(Equal(tc.expectedCertificate))

			if !apiequality.Semantic.DeepEqual(tc.expectedFailureTime, crAfter.Status.FailureTime) {
				Expect(crAfter.Status.FailureTime).To(Equal(tc.expectedFailureTime))
			}

			condition := cmutil.GetCertificateRequestCondition(&crAfter, cmapi.CertificateRequestConditionReady)
			if tc.expectedReadyConditionStatus != "" {
				Expect(condition).NotTo(BeNil(),
					"Ready condition was expected but not found: tc.expectedReadyConditionStatus == %v", tc.expectedReadyConditionStatus)
				verifyCertificateRequestReadyCondition(tc.expectedReadyConditionStatus, tc.expectedReadyConditionReason, condition)
			} else {
				Expect(condition).To(BeNil(), "Unexpected Ready condition")
			}

			if condition != nil {
				expectedEventType := corev1.EventTypeNormal
				if reconcileErr != nil || condition.Reason == cmapi.CertificateRequestReasonFailed {
					expectedEventType = corev1.EventTypeWarning
				}
				eventMessage := condition.Message
				if reconcileErr != nil {
					eventMessage = fmt.Sprintf("Temporary error. Retrying: %v", reconcileErr)
				}
				Expect(actualEvents).To(Equal(
					[]string{fmt.Sprintf("%s %s %s", expectedEventType, issuerapi.EventReasonCertificateRequestReconciler, eventMessage)}),
					"expected a single event matching the condition")
			} else {
				Expect(actualEvents).To(BeEmpty(), "Found unexpected Events without a corresponding Ready condition")
			}
		})
	}
})

func verifyCertificateRequestReadyCondition(status cmmeta.ConditionStatus, reason string, condition *cmapi.CertificateRequestCondition) {
	Expect(condition.Status).To(Equal(status), "unexpected condition status")
	validReasons := []string{
		cmapi.CertificateRequestReasonPending,
		cmapi.CertificateRequestReasonFailed,
		cmapi.CertificateRequestReasonIssued,
		cmapi.CertificateRequestReasonDenied,
	}
	Expect(validReasons).To(ContainElement(reason), "unexpected condition reason")
	Expect(condition.Reason).To(Equal(reason), "unexpected condition reason")
}
