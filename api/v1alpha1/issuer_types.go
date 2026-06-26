package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NOTE: json tags are required. Any new fields you add must have json tags for the fields to be serialized.

// SecretReference points at a single key inside a Kubernetes Secret.
type SecretReference struct {
	// Name of the Kubernetes Secret.
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// Namespace of the Kubernetes Secret.
	// +kubebuilder:validation:Required
	Namespace string `json:"namespace"`

	// Key within the Secret that holds the value.
	// +kubebuilder:validation:Required
	Key string `json:"key"`
}

// NamespacedName references a namespaced Kubernetes object by name.
type NamespacedName struct {
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// +kubebuilder:validation:Required
	Namespace string `json:"namespace"`
}

// AuthMethod selects which Machine Identity authentication method the issuer uses.
// +kubebuilder:validation:Enum=universal;kubernetes
type AuthMethod string

// Supported Machine Identity authentication methods.
const (
	AuthMethodUniversal  AuthMethod = "universal"
	AuthMethodKubernetes AuthMethod = "kubernetes"
)

// Authentication defines how the issuer authenticates with Infisical. Set a
// method and fill in the matching config block.
type Authentication struct {
	// Method selects the authentication method. One of "universal" or "kubernetes".
	// +kubebuilder:validation:Required
	Method AuthMethod `json:"method"`

	// Universal holds the configuration for Universal Auth. Required when method is "universal".
	// +optional
	Universal *UniversalAuthConfig `json:"universal,omitempty"`

	// Kubernetes holds the configuration for Kubernetes Auth. Required when method is "kubernetes".
	// +optional
	Kubernetes *KubernetesAuthConfig `json:"kubernetes,omitempty"`
}

// UniversalAuthConfig authenticates with a Machine Identity client ID and secret,
// each read from a Kubernetes Secret by reference.
type UniversalAuthConfig struct {
	// ClientIDRef references the Secret key holding the Machine Identity client ID.
	// +kubebuilder:validation:Required
	ClientIDRef SecretReference `json:"clientIdRef"`

	// ClientSecretRef references the Secret key holding the Machine Identity client secret.
	// +kubebuilder:validation:Required
	ClientSecretRef SecretReference `json:"clientSecretRef"`
}

// KubernetesAuthConfig authenticates with a Kubernetes service account token. The
// issuer mints a short-lived token for the referenced service account and presents
// it to Infisical.
type KubernetesAuthConfig struct {
	// IdentityIDRef references the Secret key holding the Machine Identity ID.
	// +kubebuilder:validation:Required
	IdentityIDRef SecretReference `json:"identityIdRef"`

	// ServiceAccountRef is the service account whose token the issuer presents to Infisical.
	// +kubebuilder:validation:Required
	ServiceAccountRef NamespacedName `json:"serviceAccountRef"`

	// ServiceAccountTokenAudiences are optional custom audiences for the minted token.
	// +optional
	ServiceAccountTokenAudiences []string `json:"serviceAccountTokenAudiences,omitempty"`
}

// TLSConfig configures how the issuer trusts the Infisical instance's TLS certificate.
type TLSConfig struct {
	// CACertificate references a Secret key holding a PEM CA certificate used to verify
	// the connection to a self-hosted Infisical.
	// +kubebuilder:validation:Required
	CACertificate SecretReference `json:"caCertificate"`
}

// IssuerSpec defines the desired state of an Issuer or ClusterIssuer.
type IssuerSpec struct {
	// URL is the base URL of the Infisical instance, e.g. "https://app.infisical.com".
	// +kubebuilder:validation:Required
	URL string `json:"url"`

	// TLS optionally configures a custom CA certificate for verifying a self-hosted
	// Infisical instance. If omitted, the system trust store is used.
	// +optional
	TLS *TLSConfig `json:"tls,omitempty"`

	// Application is the name of the Infisical PKI Application to issue through.
	// +kubebuilder:validation:Required
	Application string `json:"application"`

	// Profile is the name of the Certificate Profile to issue with.
	// +kubebuilder:validation:Required
	Profile string `json:"profile"`

	// Authentication selects and configures the Machine Identity auth method.
	// +kubebuilder:validation:Required
	Authentication Authentication `json:"authentication"`
}

// IssuerStatus defines the observed state of Issuer
type IssuerStatus struct {
	// Conditions indicate the status of the Issuer. The known condition type is `Ready`.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// Issuer is the Schema for the issuers API
type Issuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   IssuerSpec   `json:"spec,omitempty"`
	Status IssuerStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// IssuerList contains a list of Issuer
type IssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Issuer `json:"items"`
}

const (
	// ConditionReady is the condition type that indicates an Issuer/ClusterIssuer
	// is able to sign certificates. CertificateRequest controllers should not
	// attempt to sign while this condition is not True.
	ConditionReady = "Ready"
)

func init() {
	SchemeBuilder.Register(&Issuer{}, &IssuerList{})
}
