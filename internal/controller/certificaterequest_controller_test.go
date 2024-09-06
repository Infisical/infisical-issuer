package controller

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	cmutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	cmgen "github.com/cert-manager/cert-manager/test/unit/gen"
	logrtesting "github.com/go-logr/logr/testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/record"
	clock "k8s.io/utils/clock/testing"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	sampleissuerapi "github.com/Infisical/infisical-issuer/api/v1alpha1"
	"github.com/Infisical/infisical-issuer/internal/issuer/signer"
	certmanager "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

var (
	fixedClockStart = time.Date(2021, time.January, 1, 1, 0, 0, 0, time.UTC)
	fixedClock      = clock.NewFakeClock(fixedClockStart)
)

type fakeSigner struct {
	errSign error
}

func (o *fakeSigner) Sign(certmanager.CertificateRequest) ([]byte, error) {
	return []byte("fake signed certificate"), o.errSign
}

func TestCertificateRequestReconcile(t *testing.T) {
	nowMetaTime := metav1.NewTime(fixedClockStart)

	type testCase struct {
		name                         types.NamespacedName
		secretObjects                []client.Object
		issuerObjects                []client.Object
		crObjects                    []client.Object
		signerBuilder                signer.SignerBuilder
		clusterResourceNamespace     string
		expectedResult               ctrl.Result
		expectedError                error
		expectedReadyConditionStatus cmmeta.ConditionStatus
		expectedReadyConditionReason string
		expectedFailureTime          *metav1.Time
		expectedCertificate          []byte
	}
	tests := map[string]testCase{
		"success-issuer": {
			name: types.NamespacedName{Namespace: "ns1", Name: "cr1"},
			crObjects: []client.Object{
				cmgen.CertificateRequest(
					"cr1",
					cmgen.SetCertificateRequestNamespace("ns1"),
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  "issuer1",
						Group: sampleissuerapi.GroupVersion.Group,
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
			issuerObjects: []client.Object{&sampleissuerapi.Issuer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "issuer1",
					Namespace: "ns1",
				},
				Spec: sampleissuerapi.IssuerSpec{
					Authentication: sampleissuerapi.Authentication{
						UniversalAuth: sampleissuerapi.UniversalAuthDetails{
							SecretRef: sampleissuerapi.KubeSecretReference{
								Name: "issuer1-credentials",
								Key:  "clientSecret",
							},
						},
					},
				},
				Status: sampleissuerapi.IssuerStatus{
					Conditions: []sampleissuerapi.IssuerCondition{
						{
							Type:   sampleissuerapi.IssuerConditionReady,
							Status: sampleissuerapi.ConditionTrue,
						},
					},
				},
			},
			},
			secretObjects: []client.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "issuer1-credentials",
					Namespace: "ns1",
				},
			},
			},
			signerBuilder: func(*sampleissuerapi.IssuerSpec, map[string][]byte) (signer.Signer, error) {
				return &fakeSigner{}, nil
			},
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
						Group: sampleissuerapi.GroupVersion.Group,
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
			issuerObjects: []client.Object{
				&sampleissuerapi.ClusterIssuer{
					ObjectMeta: metav1.ObjectMeta{
						Name: "clusterissuer1",
					},
					Spec: sampleissuerapi.IssuerSpec{
						Authentication: sampleissuerapi.Authentication{
							UniversalAuth: sampleissuerapi.UniversalAuthDetails{
								SecretRef: sampleissuerapi.KubeSecretReference{
									Name: "clusterissuer1-credentials",
									Key:  "clientSecret",
								},
							},
						},
					},
					Status: sampleissuerapi.IssuerStatus{
						Conditions: []sampleissuerapi.IssuerCondition{
							{
								Type:   sampleissuerapi.IssuerConditionReady,
								Status: sampleissuerapi.ConditionTrue,
							},
						},
					},
				},
			},
			secretObjects: []client.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "clusterissuer1-credentials",
					Namespace: "kube-system",
				},
			}},
			signerBuilder: func(*sampleissuerapi.IssuerSpec, map[string][]byte) (signer.Signer, error) {
				return &fakeSigner{}, nil
			},
			clusterResourceNamespace:     "kube-system",
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
						Group: sampleissuerapi.GroupVersion.Group,
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
						Group: sampleissuerapi.GroupVersion.Group,
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
						Group: sampleissuerapi.GroupVersion.Group,
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
						Group: sampleissuerapi.GroupVersion.Group,
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
						Group: sampleissuerapi.GroupVersion.Group,
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
						Group: sampleissuerapi.GroupVersion.Group,
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
			issuerObjects: []client.Object{
				&sampleissuerapi.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1",
						Namespace: "ns1",
					},
					Status: sampleissuerapi.IssuerStatus{
						Conditions: []sampleissuerapi.IssuerCondition{
							{
								Type:   sampleissuerapi.IssuerConditionReady,
								Status: sampleissuerapi.ConditionFalse,
							},
						},
					},
				},
			},
			expectedError:                errIssuerNotReady,
			expectedReadyConditionStatus: cmmeta.ConditionFalse,
			expectedReadyConditionReason: cmapi.CertificateRequestReasonPending,
		},
		"issuer-secret-not-found": {
			name: types.NamespacedName{Namespace: "ns1", Name: "cr1"},
			crObjects: []client.Object{
				cmgen.CertificateRequest(
					"cr1",
					cmgen.SetCertificateRequestNamespace("ns1"),
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  "issuer1",
						Group: sampleissuerapi.GroupVersion.Group,
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
			issuerObjects: []client.Object{
				&sampleissuerapi.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1",
						Namespace: "ns1",
					},
					Spec: sampleissuerapi.IssuerSpec{
						Authentication: sampleissuerapi.Authentication{
							UniversalAuth: sampleissuerapi.UniversalAuthDetails{
								SecretRef: sampleissuerapi.KubeSecretReference{
									Name: "issuer1-credentials",
									Key:  "clientSecret",
								},
							},
						},
					},
					Status: sampleissuerapi.IssuerStatus{
						Conditions: []sampleissuerapi.IssuerCondition{
							{
								Type:   sampleissuerapi.IssuerConditionReady,
								Status: sampleissuerapi.ConditionTrue,
							},
						},
					},
				},
			},
			expectedError:                errGetAuthSecret,
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
						Group: sampleissuerapi.GroupVersion.Group,
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
			secretObjects: []client.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1-credentials",
						Namespace: "ns1",
					},
				},
			},
			issuerObjects: []client.Object{
				&sampleissuerapi.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1",
						Namespace: "ns1",
					},
					Spec: sampleissuerapi.IssuerSpec{
						Authentication: sampleissuerapi.Authentication{
							UniversalAuth: sampleissuerapi.UniversalAuthDetails{
								SecretRef: sampleissuerapi.KubeSecretReference{
									Name: "issuer1-credentials",
									Key:  "clientSecret",
								},
							},
						},
					},
					Status: sampleissuerapi.IssuerStatus{
						Conditions: []sampleissuerapi.IssuerCondition{
							{
								Type:   sampleissuerapi.IssuerConditionReady,
								Status: sampleissuerapi.ConditionTrue,
							},
						},
					},
				},
			},
			signerBuilder: func(*sampleissuerapi.IssuerSpec, map[string][]byte) (signer.Signer, error) {
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
						Group: sampleissuerapi.GroupVersion.Group,
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
			secretObjects: []client.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1-credentials",
						Namespace: "ns1",
					},
				},
			},
			issuerObjects: []client.Object{
				&sampleissuerapi.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1",
						Namespace: "ns1",
					},
					Spec: sampleissuerapi.IssuerSpec{
						Authentication: sampleissuerapi.Authentication{
							UniversalAuth: sampleissuerapi.UniversalAuthDetails{
								SecretRef: sampleissuerapi.KubeSecretReference{
									Name: "issuer1-credentials",
									Key:  "clientSecret",
								},
							},
						},
					},
					Status: sampleissuerapi.IssuerStatus{
						Conditions: []sampleissuerapi.IssuerCondition{
							{
								Type:   sampleissuerapi.IssuerConditionReady,
								Status: sampleissuerapi.ConditionTrue,
							},
						},
					},
				},
			},
			signerBuilder: func(*sampleissuerapi.IssuerSpec, map[string][]byte) (signer.Signer, error) {
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
						Group: sampleissuerapi.GroupVersion.Group,
						Kind:  "Issuer",
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionReady,
						Status: cmmeta.ConditionUnknown,
					}),
				),
			},
			secretObjects: []client.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1-credentials",
						Namespace: "ns1",
					},
				},
			},
			issuerObjects: []client.Object{
				&sampleissuerapi.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1",
						Namespace: "ns1",
					},
					Spec: sampleissuerapi.IssuerSpec{
						Authentication: sampleissuerapi.Authentication{
							UniversalAuth: sampleissuerapi.UniversalAuthDetails{
								SecretRef: sampleissuerapi.KubeSecretReference{
									Name: "issuer1-credentials",
									Key:  "clientSecret",
								},
							},
						},
					},
					Status: sampleissuerapi.IssuerStatus{
						Conditions: []sampleissuerapi.IssuerCondition{
							{
								Type:   sampleissuerapi.IssuerConditionReady,
								Status: sampleissuerapi.ConditionTrue,
							},
						},
					},
				},
			},
			signerBuilder: func(*sampleissuerapi.IssuerSpec, map[string][]byte) (signer.Signer, error) {
				return &fakeSigner{}, nil
			},
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
						Group: sampleissuerapi.GroupVersion.Group,
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
			issuerObjects: []client.Object{
				&sampleissuerapi.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1",
						Namespace: "ns1",
					},
					Spec: sampleissuerapi.IssuerSpec{
						Authentication: sampleissuerapi.Authentication{
							UniversalAuth: sampleissuerapi.UniversalAuthDetails{
								SecretRef: sampleissuerapi.KubeSecretReference{
									Name: "issuer1-credentials",
									Key:  "clientSecret",
								},
							},
						},
					},
					Status: sampleissuerapi.IssuerStatus{
						Conditions: []sampleissuerapi.IssuerCondition{
							{
								Type:   sampleissuerapi.IssuerConditionReady,
								Status: sampleissuerapi.ConditionTrue,
							},
						},
					},
				},
			},
			secretObjects: []client.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1-credentials",
						Namespace: "ns1",
					},
				},
			},
			signerBuilder: func(*sampleissuerapi.IssuerSpec, map[string][]byte) (signer.Signer, error) {
				return &fakeSigner{}, nil
			},
			expectedCertificate:          nil,
			expectedFailureTime:          &nowMetaTime,
			expectedReadyConditionStatus: cmmeta.ConditionFalse,
			expectedReadyConditionReason: cmapi.CertificateRequestReasonDenied,
		},
	}

	scheme := runtime.NewScheme()
	require.NoError(t, sampleissuerapi.AddToScheme(scheme))
	require.NoError(t, cmapi.AddToScheme(scheme))
	require.NoError(t, corev1.AddToScheme(scheme))

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			eventRecorder := record.NewFakeRecorder(100)
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tc.secretObjects...).
				WithObjects(tc.crObjects...).
				WithObjects(tc.issuerObjects...).
				WithStatusSubresource(tc.issuerObjects...).
				WithStatusSubresource(tc.crObjects...).
				Build()

			// current:
			// type CertificateRequestReconciler struct {
			// 	client.Client
			// 	Scheme *runtime.Scheme
			// }

			// example issuer one:
			controller := CertificateRequestReconciler{
				Client:                   fakeClient,
				Scheme:                   scheme,
				ClusterResourceNamespace: tc.clusterResourceNamespace,
				SignerBuilder:            tc.signerBuilder,
				CheckApprovedCondition:   true,
				Clock:                    fixedClock,    // x
				recorder:                 eventRecorder, // x
			}

			var crBefore cmapi.CertificateRequest
			if err := fakeClient.Get(context.TODO(), tc.name, &crBefore); err != nil {
				require.NoError(t, client.IgnoreNotFound(err), "unexpected error from fake client")
			}

			result, reconcileErr := controller.Reconcile(
				ctrl.LoggerInto(context.TODO(), logrtesting.NewTestLogger(t)),
				reconcile.Request{NamespacedName: tc.name},
			)

			var actualEvents []string
			for {
				select {
				case e := <-eventRecorder.Events:
					actualEvents = append(actualEvents, e)
					continue
				default:
					break
				}
				break
			}
			if tc.expectedError != nil {
				assertErrorIs(t, tc.expectedError, reconcileErr)
				if name == "secret-get-error" {
					assert.Equal(t, tc.expectedResult, result, "Unexpected result for secret-get-error")
				}
			} else {
				assert.NoError(t, reconcileErr)
			}

			assert.Equal(t, tc.expectedResult, result, "Unexpected result")

			var crAfter cmapi.CertificateRequest
			if err := fakeClient.Get(context.TODO(), tc.name, &crAfter); err != nil {
				require.NoError(t, client.IgnoreNotFound(err), "unexpected error from fake client")
				return
			}

			if crBefore.ResourceVersion == crAfter.ResourceVersion {
				assert.Empty(t, actualEvents, "Events should only be created if the CertificateRequest is modified")
				return
			}

			assert.Equal(t, tc.expectedCertificate, crAfter.Status.Certificate)

			if !apiequality.Semantic.DeepEqual(tc.expectedFailureTime, crAfter.Status.FailureTime) {
				assert.Equal(t, tc.expectedFailureTime, crAfter.Status.FailureTime)
			}

			condition := cmutil.GetCertificateRequestCondition(&crAfter, cmapi.CertificateRequestConditionReady)
			if tc.expectedReadyConditionStatus != "" {
				if assert.NotNilf(
					t,
					condition,
					"Ready condition was expected but not found: tc.expectedReadyConditionStatus == %v",
					tc.expectedReadyConditionStatus,
				) {
					verifyCertificateRequestReadyCondition(t, tc.expectedReadyConditionStatus, tc.expectedReadyConditionReason, condition)
				}
			} else {
				assert.Nil(t, condition, "Unexpected Ready condition")
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
				assert.Equal(
					t,
					[]string{fmt.Sprintf("%s %s %s", expectedEventType, sampleissuerapi.EventReasonCertificateRequestReconciler, eventMessage)},
					actualEvents,
					"expected a single event matching the condition",
				)
			} else {
				assert.Empty(t, actualEvents, "Found unexpected Events without a corresponding Ready condition")
			}
		})
	}
}

type errorInjectedClient struct {
	client.Client
	errorOn func(action string, obj runtime.Object) bool
}

func (c *errorInjectedClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if c.errorOn("get", obj) {
		return errors.New("simulated get error")
	}
	return c.Client.Get(ctx, key, obj, opts...)
}

func assertErrorIs(t *testing.T, expectedError, actualError error) {
	if !assert.Error(t, actualError) {
		return
	}
	assert.Truef(t, errors.Is(actualError, expectedError), "unexpected error type. expected: %v, got: %v", expectedError, actualError)
}

func verifyCertificateRequestReadyCondition(t *testing.T, status cmmeta.ConditionStatus, reason string, condition *cmapi.CertificateRequestCondition) {
	assert.Equal(t, status, condition.Status, "unexpected condition status")
	validReasons := sets.NewString(
		cmapi.CertificateRequestReasonPending,
		cmapi.CertificateRequestReasonFailed,
		cmapi.CertificateRequestReasonIssued,
		cmapi.CertificateRequestReasonDenied,
	)
	assert.Contains(t, validReasons, reason, "unexpected condition reason")
	assert.Equal(t, reason, condition.Reason, "unexpected condition reason")
}
