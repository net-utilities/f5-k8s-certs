#!/usr/bin/python3
from F5Cert import F5rest, logger, KubeClient, Settings

[token, cluster_api_url, namespace] = Settings().get_settings()

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

    try:
        f5rest.update_management_cert(c['cert_key']['cert'],
            c['cert_key']['key'])
    except BaseException as e:
        logger.error(f'Failed to update management certificate on {c["device_fqdn"]}')
        logger.error(e)
        continue