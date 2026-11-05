package controller

import (
	"context"
	"errors"

	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	cmutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	cmgen "github.com/cert-manager/cert-manager/test/unit/gen"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	issuerapi "github.com/Infisical/infisical-issuer/api/v1alpha1"
	"github.com/Infisical/infisical-issuer/internal/auth"
	"github.com/Infisical/infisical-issuer/internal/cache"
	"github.com/Infisical/infisical-issuer/internal/issuer/signer"
)

var _ = Describe("CertificateRequest retries", func() {
	newApprovedCR := func() *cmapi.CertificateRequest {
		return cmgen.CertificateRequest(
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
		)
	}

	It("records the Infisical request id for a certificate issued synchronously", func() {
		scheme := runtime.NewScheme()
		Expect(issuerapi.AddToScheme(scheme)).To(Succeed())
		Expect(cmapi.AddToScheme(scheme)).To(Succeed())
		Expect(corev1.AddToScheme(scheme)).To(Succeed())

		cr := newApprovedCR()
		issuer := &issuerapi.Issuer{
			ObjectMeta: metav1.ObjectMeta{Name: "issuer1", Namespace: "ns1"},
			Status:     readyIssuerStatus(),
		}
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(cr, issuer).
			WithStatusSubresource(cr, issuer).
			Build()

		issued := func(client.Client, *auth.Resolver, *issuerapi.IssuerSpec, cache.ClientCacheKey, string) (signer.Signer, error) {
			return &fakeSigner{result: signer.SignResult{
				Certificate: []byte("fake signed certificate"),
				CA:          []byte("fake signed certificate"),
				RequestID:   "req-issued",
			}}, nil
		}
		controller := CertificateRequestReconciler{
			Client:                 fakeClient,
			Scheme:                 scheme,
			SignerBuilder:          issued,
			CheckApprovedCondition: true,
			Clock:                  fixedClock,
			recorder:               record.NewFakeRecorder(10),
		}

		name := types.NamespacedName{Namespace: "ns1", Name: "cr1"}
		_, err := controller.Reconcile(ctrl.LoggerInto(context.TODO(), logr.Discard()), reconcile.Request{NamespacedName: name})
		Expect(err).NotTo(HaveOccurred())

		var after cmapi.CertificateRequest
		Expect(fakeClient.Get(context.TODO(), name, &after)).To(Succeed())
		Expect(after.Annotations).To(HaveKeyWithValue(requestIDAnnotation, "req-issued"))
		Expect(after.Status.Certificate).To(Equal([]byte("fake signed certificate")))
	})

	It("still saves an issued certificate when recording the request id fails", func() {
		scheme := runtime.NewScheme()
		Expect(issuerapi.AddToScheme(scheme)).To(Succeed())
		Expect(cmapi.AddToScheme(scheme)).To(Succeed())
		Expect(corev1.AddToScheme(scheme)).To(Succeed())

		cr := newApprovedCR()
		issuer := &issuerapi.Issuer{
			ObjectMeta: metav1.ObjectMeta{Name: "issuer1", Namespace: "ns1"},
			Status:     readyIssuerStatus(),
		}
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(cr, issuer).
			WithStatusSubresource(cr, issuer).
			WithInterceptorFuncs(interceptor.Funcs{
				Patch: func(context.Context, client.WithWatch, client.Object, client.Patch, ...client.PatchOption) error {
					return errors.New("simulated patch failure")
				},
			}).
			Build()

		issued := func(client.Client, *auth.Resolver, *issuerapi.IssuerSpec, cache.ClientCacheKey, string) (signer.Signer, error) {
			return &fakeSigner{result: signer.SignResult{
				Certificate: []byte("fake signed certificate"),
				CA:          []byte("fake signed certificate"),
				RequestID:   "req-issued",
			}}, nil
		}
		controller := CertificateRequestReconciler{
			Client:                 fakeClient,
			Scheme:                 scheme,
			SignerBuilder:          issued,
			CheckApprovedCondition: true,
			Clock:                  fixedClock,
			recorder:               record.NewFakeRecorder(10),
		}

		name := types.NamespacedName{Namespace: "ns1", Name: "cr1"}
		_, err := controller.Reconcile(ctrl.LoggerInto(context.TODO(), logr.Discard()), reconcile.Request{NamespacedName: name})
		Expect(err).NotTo(HaveOccurred())

		var after cmapi.CertificateRequest
		Expect(fakeClient.Get(context.TODO(), name, &after)).To(Succeed())
		Expect(after.Status.Certificate).To(Equal([]byte("fake signed certificate")))
		ready := cmutil.GetCertificateRequestCondition(&after, cmapi.CertificateRequestConditionReady)
		Expect(ready).NotTo(BeNil())
		Expect(ready.Reason).To(Equal(cmapi.CertificateRequestReasonIssued))
	})

	Describe("ignoreOwnStatusWrites", func() {
		update := func(oldCR, newCR *cmapi.CertificateRequest) bool {
			return ignoreOwnStatusWrites().Update(event.UpdateEvent{ObjectOld: oldCR, ObjectNew: newCR})
		}

		It("ignores a change to only the Ready condition, certificate and failure time", func() {
			oldCR := newApprovedCR()
			newCR := oldCR.DeepCopy()
			newCR.ResourceVersion = "2"
			newCR.Status.Certificate = []byte("cert")
			now := metav1.Now()
			newCR.Status.FailureTime = &now
			for i := range newCR.Status.Conditions {
				if newCR.Status.Conditions[i].Type == cmapi.CertificateRequestConditionReady {
					newCR.Status.Conditions[i].Message = "Temporary error. Retrying: something changed"
				}
			}
			Expect(update(oldCR, newCR)).To(BeFalse())
		})

		It("reacts to approval, annotations and spec changes", func() {
			unapproved := newApprovedCR()
			unapproved.Status.Conditions = unapproved.Status.Conditions[1:]
			Expect(update(unapproved, newApprovedCR())).To(BeTrue())

			annotated := newApprovedCR()
			annotated.Annotations = map[string]string{"example": "changed"}
			Expect(update(newApprovedCR(), annotated)).To(BeTrue())

			respec := newApprovedCR()
			respec.Spec.Request = []byte("different csr")
			Expect(update(newApprovedCR(), respec)).To(BeTrue())
		})
	})
})
