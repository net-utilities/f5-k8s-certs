import requests, os, re, hashlib, time, base64
from F5Cert.logger.logger import logger

import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class KubeClient:
    def __init__(self, token, cluster_url, namespace, verify_ssl=False):
        self._token = token
        self.cluster_url = cluster_url
        self.verify_ssl = verify_ssl
        self.namespace = namespace
        self._session = None

    @property
    def session(self):
        if not self._session:
            self._session = requests.Session()
            self._session.headers.update({'Authorization': f'Bearer {self._token}'})
            self._session.verify = self.verify_ssl
        return self._session

    def get_secret(self, name):
        result = self.session.get(
            f'{self.cluster_url}/api/v1/namespaces/f5-certs/secrets/{name}')
        data = result.json()
        return data['data']

    def get_f5_credentials(self, name):
        data = self.get_secret(name)
        username = data.get('F5_PASSWORD')
        password = data.get('F5_PASSWORD')
        return [
            base64.b64decode(username).decode('utf-8'),
            base64.b64decode(password).decode('utf-8'),
        ]

    def get_cert_key(self, name):
        data = self.get_secret(name)
        certificate = data.get('tls.crt')
        key = data.get('tls.key')
        return [
            base64.b64decode(certificate),
            base64.b64decode(key)
        ]

    def get_certificates(self):
        logger.debug(f'Getting {self.cluster_url}/apis/cert-manager.io/v1/namespaces/{self.namespace}/certificates')
        result = self.session.get(
            f'{self.cluster_url}/apis/cert-manager.io/v1/namespaces/{self.namespace}/certificates')
        data = result.json()

        logger.debug(data)
        
        certificates = []

        for c in data['items']:
            if not 'labels' in c['metadata']:
                continue
            labels = c['metadata']['labels']
            if labels.get('f5-cert-type') != 'management':
                continue

            f5_cert_type = labels.get('f5-cert-type')
            f5_auth_ref = labels.get('f5-auth-ref')
            f5_device_fqdn = labels.get('f5-device-fqdn')
            cert_secret_name = c['spec']['secretName']

            credentials = self.get_f5_credentials(f5_auth_ref)
            cert_key = self.get_cert_key(cert_secret_name)

            certificates.append([
                f5_cert_type,
                f5_device_fqdn,
                credentials,
                cert_key,
            ])

        return certificates
