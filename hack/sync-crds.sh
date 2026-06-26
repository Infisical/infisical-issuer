#!/usr/bin/env bash
# Derives the Helm chart CRD templates from the controller-gen output in
# config/crd/bases so the CRD schema is maintained in exactly one place. The only
# Helm-specific addition is the chart labels block; the spec (schema) is copied
# verbatim from the generated CRD. Run via `make sync-crds`, which regenerates
# config/crd/bases first.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CRD_DIR="$ROOT/config/crd/bases"
HELM_DIR="$ROOT/helm-charts/infisical-pki-issuer/templates"

render() {
  local src="$1" name="$2" dest="$3"
  local ver
  ver="$(awk -F': ' '/controller-gen.kubebuilder.io\/version/{gsub(/ /,"",$2); print $2; exit}' "$src")"
  {
    echo "apiVersion: apiextensions.k8s.io/v1"
    echo "kind: CustomResourceDefinition"
    echo "metadata:"
    echo "  name: $name"
    echo "  annotations:"
    echo "    controller-gen.kubebuilder.io/version: $ver"
    echo "  labels:"
    echo '  {{- include "infisical-pki-issuer.labels" . | nindent 4 }}'
    # Everything from "spec:" onward is the generated schema, copied as-is.
    awk '/^spec:/{p=1} p' "$src"
  } >"$dest"
  echo "rendered $dest"
}

render "$CRD_DIR/infisical-issuer.infisical.com_issuers.yaml" \
  "issuers.infisical-issuer.infisical.com" \
  "$HELM_DIR/issuer-crd.yaml"
render "$CRD_DIR/infisical-issuer.infisical.com_clusterissuers.yaml" \
  "clusterissuers.infisical-issuer.infisical.com" \
  "$HELM_DIR/clusterissuer-crd.yaml"
