#!/usr/bin/python3
from F5Cert import F5rest, logger, KubeClient, Settings

[token, cluster_api_url, namespace] = Settings().get_settings()

kube_client = KubeClient(token, cluster_api_url, namespace)
certificates = kube_client.get_certificates()

for c in certificates:

    [f5_cert_type, f5_device_fqdn, credentials, cert_key] = c
    [username, password] = credentials
    [cert, key] = cert_key

    if f5_cert_type != 'management':
        logger.error('Certificate other than management certificates are not supported yet')
        continue

    f5rest = F5rest(
        username,
        password,
        f5_device_fqdn,
        'management',
        False
    )

    try:
        f5rest.update_management_cert(cert,
                                      key)
    except BaseException as e:
        logger.error(f'Failed to update management certificate on {c["device_fqdn"]}')
        logger.error(e)
        continue
