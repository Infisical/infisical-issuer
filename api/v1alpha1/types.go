package v1alpha1

// Event source and reasons used when recording Kubernetes events.
const (
	EventSource                             = "infisical-issuer"
	EventReasonCertificateRequestReconciler = "CertificateRequestReconciler"
	EventReasonIssuerReconciler             = "IssuerReconciler"
)
