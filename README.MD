# F5 management certificate updater for Kubernetes

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

When a certificate with the correct labels has been found the script gets the F5 credentials and the cert + key from the Certificate secret and updates it on the F5 device.

# Using this project in Kubernetes

The following guide will guide you on how to get this started in your Kubernetes cluster.
It does assume you have a bit of experience with Kubernetes and Kubectl, but not much.

## Prerequisites
* The Kubernetes cluster running the BatchJob which updates the certificates needs to 
have access to any F5 on port 443 in order to update the management certificates.
* You need a DNS record pointing to the F5.
* You need a functioning Certificate Manager able to sign a certificate for this DNS record
If you don't I have a guide for this [here](https://loadbalancing.se/2021/01/02/internal-rancher-ha-letsencrypt-google-cloud-dns/).
* You need [helm](https://helm.sh) installed on your client.

## Deploy the help template

1. Make sure your KUBECONFIG is configured to use the cluster that will runt the app.
2. Go to `Chart/` in this repository.
3. Optional: Configure the Values.yaml file.
The default options works fine but you may want to use your own namespace name.
4. Run `helm template f5-certs -f Values.yaml .` to see the outcome of the installation.
5. If you're happy, run `helm install f5-certs -f Values.yaml .` to install.

Now you have a BatchJob which will run at 8am every morning unless you changed the default setting.

## Configure F5 Credentials and Certificates

1. Create a secret in your chosen namespace:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: f5-credentials
  namespace: f5-certs    # Important: Change this to the namespace name of your choice
type: Opaque
data:
  F5_USERNAME: YWRtaW4= # Both the username and the credentials has to be Base64 encoded
  F5_PASSWORD: aHR0cHM6Ly93d3cueW91dHViZS5jb20vd2F0Y2g/dj1kUXc0dzlXZ1hjUQ==
```

2. Create the certificates you want to manage with the BatchJob:

```yaml
---
apiVersion: cert-manager.io/v1alpha2
kind: Certificate
metadata:
  name: bigip02-xip-se
  namespace: f5-certs
  labels:
    f5-cert-type: "management"
    f5-auth-ref: "f5-credentials"         # Reference to the secret holding the credentials (same namespace)
    f5-device-fqdn: "bigip01.xip.se"  # The FQDN to the F5 device that will be updated
spec:
  secretName: f5-cert
  issuerRef:
    name: letsencrypt-issuer
    kind: ClusterIssuer       # Depending on your setup this might be "Issuer".
  dnsNames:
  - "bigip01.xip.se"
---
apiVersion: cert-manager.io/v1alpha2
kind: Certificate
metadata:
  name: bigip02-xip-se
  namespace: f5-certs
  labels:
    f5-cert-type: "management"
    f5-auth-ref: "f5-credentials"   # Reference to the secret holding the credentials (same namespace)
    f5-device-fqdn: "bigip02.domain.com"  # The FQDN to the F5 device that will be updated
spec:
  secretName: f5-cert
  issuerRef:
    name: letsencrypt-issuer
    kind: ClusterIssuer
  dnsNames:
  - "bigip02.xip.se"
```

*Note how there are two certs above with two different domains, but the same credentials.
You can choose to create new credentials or create new ones if necessary.*

## Run the BatchJob manually

To test the BatchJob you can fire one off manually like this:

```bash
kubectl create job -n f5-certs --from=cronjob/cert-updater cert-updater-01
kubectl logs -n f5-certs job/cert-updater-01 
2022-08-10 18:42:20,901 - main - INFO - Restarting httpd
2022-08-10 18:42:25,905 - main - INFO - Waiting for management interface to restart
Certificate has been updated and the httpd interface is responding
```
Creating yet another job shows that the certificate does not need to be updated.

```
kubectl create job -n f5-certs --from=cronjob/cert-updater cert-updater-02
kubectl logs -n f5-certs job/cert-updater-02
2022-08-10 18:47:21,844 - main - INFO - Local certificates matches the remote certificates, no need to update on bigip.domain.com
```

# Contributing
Oh, I'd love some contributions to the project. Just two small requests:

* Try to keep them as small as possible.
* Keep the language to Python.
* Be nice.

## Setting up a development environment

Running the Python code within the cluster and outside differs a bit.
Within the cluster the script has access to the auth token and cluster 
url via the service account (files are mounted into the container)
but when running and debugging we want to run the code on our client.

Thus we need to replace these mounted files with environment variables. 
More on that below.

### Prerequisites

* A Kubernetes cluster.
* An F5 device with a DNS pointing to it.
* You need a functioning Certificate Manager able to sign a certificate for this DNS record.
If you don't I have a guide for this [here](https://loadbalancing.se/2021/01/02/internal-rancher-ha-letsencrypt-google-cloud-dns/).

### Setup a namespace, Secret with F5 Credentials, and a Certificate

1. Create a namespace where you can host the certificate:

`kubectl create ns f5-certs`

2. Follow [the steps below](#Configure F5 Credentials and Certificate) to add the F5 Credentials and Certificate.

3. Either use `export` or set the following environment variables in your IDE:

| Name            | Mandatory | DEFAULT | Description                                                  |
|-----------------|-----------|---------|--------------------------------------------------------------|
| ENVIRONMENT     | Yes       |         | Needs to be set to DEV if developing locally                 |
| KUBE_TOKEN      | Yes       |         | Bearer token to the Kubernetes cluster                       |
| CLUSTER_API_URL | Yes       |         | Address to the Kubernetes kluster api (just before /api/...) |
| NAMESPACE       | Yes       |         | Where the certificates and the batch job resides             |
| LOG_LEVEL       | No        | INFO    | Can be either INFO or DEBUG, defaults to INFO                |

Once these things are in place, just run `main.py` to test the script.

## Debugging the docker container
Once the code works you your client you might want to test it in the docker container.
Since we're not using Kubernetes for this particular step you need to define the same
environment variables again.

Here's a useful docker-compose example:

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

The following Pod can be used to troubleshoot the script in Kubernetes. 
Just apply the config below (replace with your own image if you have built one).

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
