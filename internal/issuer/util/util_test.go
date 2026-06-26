package util

import (
	"testing"

	issuerapi "github.com/Infisical/infisical-issuer/api/v1alpha1"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestSetReadyCondition(t *testing.T) {
	var issuerStatus issuerapi.IssuerStatus

	SetReadyCondition(&issuerStatus, 1, metav1.ConditionTrue, "Reason1", "message1")
	assert.Equal(t, "message1", GetReadyCondition(&issuerStatus).Message)
	assert.True(t, IsReady(&issuerStatus))

	SetReadyCondition(&issuerStatus, 2, metav1.ConditionFalse, "Reason2", "message2")
	assert.Equal(t, "message2", GetReadyCondition(&issuerStatus).Message)
	assert.False(t, IsReady(&issuerStatus))
}
