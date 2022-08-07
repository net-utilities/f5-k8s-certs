#!/usr/bin/python3
from F5Cert import F5rest, logger, KubeClient
import os

env = os.environ.get('ENVIRONMENT', 'PROD')
if env == 'DEV':
    token = os.environ.get('KUBE_TOKEN')
    cluster_api_url = os.environ.get('CLUSTER_API_URL')
else:
    with open('/var/run/secrets/kubernetes.io/serviceaccount/token') as f:
        token = f.read()
    cluster_api_url = f'https://{os.environ.get("KUBERNETES_SERVICE_HOST")}:{os.environ.get("KUBERNETES_PORT_443_TCP_PORT")}'

namespace = os.environ.get('NAMESPACE')

if [x for x in [token, cluster_api_url, namespace] if x is None]:
    logger.error('Missing one or more environment variables, please check the README')


kube_client = KubeClient(token, cluster_api_url, namespace)

certificates = kube_client.get_certificates()

for c in certificates:

    if c['cert_type'] != 'management':
        logger.error('Certificate other than management certificates are not supported yet')
        continue

    f5rest = F5rest(
        c['credentials']['username'],
        c['credentials']['password'],
        c['device_fqdn'],
        'management',
        False
    )

    f5rest.update_management_cert(c['cert_key']['cert'],
        c['cert_key']['key'])
