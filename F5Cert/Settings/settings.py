#!/usr/bin/python3
import os

class Settings:

    def __init__(self):
        self.environment = os.environ.get('ENVIRONMENT', 'PROD')

    def get_k8s_settings(self):
        with open('/var/run/secrets/kubernetes.io/serviceaccount/token') as f:
            token = f.read()
        cluster_api_url = f'https://{os.environ.get("KUBERNETES_SERVICE_HOST")}:{os.environ.get("KUBERNETES_PORT_443_TCP_PORT")}'
        return [token, cluster_api_url]

    def get_dev_settings(self):
        token = os.environ.get('KUBE_TOKEN')
        cluster_api_url = os.environ.get('CLUSTER_API_URL')
        return [token, cluster_api_url]

    def get_settings(self):

        namespace = os.environ.get('NAMESPACE')
        [token, cluster_api_url] = self.get_dev_settings() if self.env == 'DEV' else self.get_k8s_settings()

        if token is None:
            raise ValueError("Missing token")
        if cluster_api_url is None:
            raise ValueError("Missing cluster API url")
        if namespace is None:
            raise ValueError("Missing namespace")

        return [token, cluster_api_url, namespace]