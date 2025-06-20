cd infisical-pki-issuer
helm dependency update
helm package .
for i in *.tgz; do
    [ -f "$i" ] || break
    cloudsmith push helm --republish infisical/helm-charts "$i"
done
cd ..