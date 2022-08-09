# This is still a work in progress. Use at own risk

# F5 certificate manager

This project uses the Kubernetes cert-manager to maintain ***management*** certificates on F5 devices.
There is a plan to traffic management certificates in the future but do not hold your breath. :)

# How it works
A BatchJob is scheduled in Kubernetes with a service account which is allowed to read:

* Secrets
* Certificates

The BatchJob looks for Certificate objects with the following labels:

| Name           | Value        | Description                                                                                      |
|----------------|--------------|--------------------------------------------------------------------------------------------------|
| f5-cert-type   | "management" | To support other certificates in the future                                                      |
| f5-auth-ref    | string       | The name of the secret that contains the credentials to the F5 device that uses this certificate |
| f5-device-fqdn | string       | The FQDN to the device that uses this certificate                                                |

Example Certificate resource:
```yaml
apiVersion: cert-manager.io/v1alpha2
kind: Certificate
metadata:
  name: bigip-xip-se
  namespace: f5-certs
  labels:
    f5-cert-type: "management"      # Only management certs supported at the moment
    f5-auth-ref: "f5-credentials"   # Reference to the secret holding the credentials (same namespace)
    f5-device-fqdn: "bigip.xip.se"  # The FQDN to the F5 device that will be updated
spec:
  secretName: f5-cert
  issuerRef:
    name: letsencrypt-issuer
    kind: ClusterIssuer
  dnsNames:
  - "bigip.xip.se"
```

When a certificate with the correct labels has been found the script gets the F5 credentials and the cert + key from the Certificate secret and updates it on the F5 device.


# Contributing
Oh, I'd love some contributions to the project. Just two small requests:

* Try to keep them as small as possible
* Keep the language to Python

## Getting started with development

* A kubernetes cluster
* An F5 device

Below are the environment variables that must be set:

| Name            | Mandatory | DEFAULT | Description                                                  |
|-----------------|-----------|---------|--------------------------------------------------------------|
| ENVIRONMENT     | Yes       |         | Needs to be set to DEV if developing locally                 |
| KUBE_TOKEN      | Yes       |         | Bearer token to the Kubernetes cluster                       |
| CLUSTER_API_URL | Yes       |         | Address to the Kubernetes kluster api (just before /api/...) |
| NAMESPACE       | Yes       |         | Where the certificates and the batch job resides             |
| LOG_LEVEL       | No        | INFO    | Can be either INFO or DEBUG, defaults to                     |

Docker-Compose DEV example

```yaml
# This file is to test the container during development
# Don't use this in prod

version: "3.9"
services:
  app:
    build: .
    environment:
      ENVIRONMENT: DEV
      CLUSTER_API_URL: https://rancher.domain.com/k8s/clusters/c-abcde
      KUBE_TOKEN: <token>
      NAMESPACE: f5-certs
```

# Debug pod

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: debug-container
  namespace: f5-certs
  labels:
    app: ubuntu
spec:
  containers:
  - image: bigipreport/f5-k8s-certs:latest
    command:
      - "sleep"
      - "604800"
    imagePullPolicy: Always
    name: ubuntu
  restartPolicy: Always
  serviceAccountName: f5-certs-sa
```

# Using this project in Kubernetes

Coming up...
