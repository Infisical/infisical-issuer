<h1 align="center">
  <img width="300" src="/resources/logo.svg#gh-dark-mode-only" alt="infisical">
</h1>
<p align="center">
  <p align="center"><b>Infisical PKI Issuer</b>: a cert-manager external issuer that issues X.509 certificates from Infisical PKI.</p>
</p>

<h4 align="center">
  |
  <a href="https://infisical.com/docs/documentation/platform/pki/overview">Documentation</a>
  |
  <a href="https://www.infisical.com">Website</a>
  |
  <a href="https://infisical.com/slack">Slack</a>
  |
</h4>

<h4 align="center">
  <a href="https://github.com/infisical/infisical/blob/main/CONTRIBUTING.md">
    <img src="https://img.shields.io/badge/PRs-Welcome-brightgreen" alt="PRs welcome!" />
  </a>
  <a href="https://infisical.com/slack">
    <img src="https://img.shields.io/badge/chat-on%20Slack-blueviolet" alt="Slack community channel" />
  </a>
  <a href="https://twitter.com/infisical">
    <img src="https://img.shields.io/twitter/follow/infisical?label=Follow" alt="Infisical Twitter" />
  </a>
</h4>

## Introduction

[Infisical PKI](https://infisical.com/docs/documentation/platform/pki/overview) is an [Infisical](https://infisical.com/) service that can setup and manage private CAs, as well as issue private certifiates.

[cert-manager](https://cert-manager.io/) is a Kubernetes add-on to automate the management and issuance of TLS certificates from various issuing sources. It ensures that certificates are valid and up to date periodically, and attempts to renew certificates at an appropriate time before expiry.

Infisical PKI Issuer is an addon (see https://cert-manager.io/docs/configuration/external/) to cert-manager that signs off certificate requests using Infisical PKI. The issuer is perfect for getting X.509 certificates for ingresses and other Kubernetes resources and capable of automatically renewing certificates as needed.

For information on how to use the issuer, please refer to the [Infisical PKI documentation](https://infisical.com/docs/documentation/platform/pki/overview).

## Security

Please do not file GitHub issues or post on our public forum for security vulnerabilities, as they are public!

Infisical takes security issues very seriously. If you have any concerns about Infisical or believe you have uncovered a vulnerability, please get in touch via the e-mail address security@infisical.com. In the message, try to provide a description of the issue and ideally a way of reproducing it. The security team will get back to you as soon as possible.

Note that this security address should be used only for undisclosed vulnerabilities. Please report any security problems to us before disclosing it publicly.

## Contributing

Whether it's big or small, we love contributions. Check out our guide to see how to [get started](https://infisical.com/docs/contributing/getting-started).

Not sure where to get started? Join our <a href="https://infisical.com/slack">Slack</a>, and ask us any questions there.