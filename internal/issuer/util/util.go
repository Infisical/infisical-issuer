package util

import (
	"fmt"

	issuerapi "github.com/Infisical/infisical-issuer/api/v1alpha1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func GetSpecAndStatus(issuer client.Object) (*issuerapi.IssuerSpec, *issuerapi.IssuerStatus, error) {
	switch t := issuer.(type) {
	case *issuerapi.Issuer:
		return &t.Spec, &t.Status, nil
	case *issuerapi.ClusterIssuer:
		return &t.Spec, &t.Status, nil
	default:
		return nil, nil, fmt.Errorf("not an issuer type: %t", t)
	}
}

func SetReadyCondition(status *issuerapi.IssuerStatus, generation int64, conditionStatus metav1.ConditionStatus, reason, message string) {
	meta.SetStatusCondition(&status.Conditions, metav1.Condition{
		Type:               issuerapi.ConditionReady,
		Status:             conditionStatus,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: generation,
	})
}

func GetReadyCondition(status *issuerapi.IssuerStatus) *metav1.Condition {
	return meta.FindStatusCondition(status.Conditions, issuerapi.ConditionReady)
}

func IsReady(status *issuerapi.IssuerStatus) bool {
	return meta.IsStatusConditionTrue(status.Conditions, issuerapi.ConditionReady)
}
