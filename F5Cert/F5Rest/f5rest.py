import requests, os, re, hashlib, time, io
from typing import Optional
from F5Cert.logger.logger import logger

import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class F5rest:
    def __init__(self, username: str, password: str, device: str, name: str, verify_ssl=False):
        self.device = device
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.cert_name = f'{name}.crt'
        self.key_name = f'{name}.key'
        self._session = None

    @property
    def session(self):
        if not self._session:
            body = {
                'username': self.username,
                'password': self.password,
                'loginProviderName': 'tmos'
            }

            token_response = requests.post(
                f'https://{self.device}/mgmt/shared/authn/login',
                verify=self.verify_ssl,
                auth=(self.username, self.password), json=body) \
                .json()

            token = token_response['token']['token']
            self._session = requests.Session()
            self._session.headers.update({'X-F5-Auth-Token': token})
            self._session.verify = self.verify_ssl
        return self._session

    def upload_file(self, name: str, data: bytes):

        headers = {
            'Content-Type': 'application/octet-stream',
        }

        file_obj = io.BytesIO(data)

        chunk_size = 512 * 1024
        size = file_obj.getbuffer().nbytes
        end_point = f'https://192.168.70.245/mgmt/shared/file-transfer/uploads/{name}'

        start = 0

        while True:
            file_slice = file_obj.read(chunk_size)
            if not file_slice:
                break

            current_bytes = len(file_slice)
            if current_bytes < chunk_size:
                end = size
            else:
                end = start + current_bytes

            content_range = f'{start}-{end - 1}/{size}'
            headers['Content-Range'] = content_range
            self.session.post(end_point,
                              data=file_slice,
                              headers=headers,
                              verify=self.verify_ssl)
            start += current_bytes

    def run_bash_command(self, command: str, timeout=None) -> Optional[str]:

        payload = {
            'command': 'run',
            'utilCmdArgs': f"-c '{command}'"
        }

        response = self.session.post(f'https://{self.device}/mgmt/tm/util/bash',
                                     json=payload, verify=self.verify_ssl, timeout=timeout)

        if response.status_code != 200:
            raise RuntimeError(f'Command {command} failed to run on {self.device}')

        response_json = response.json()

        if 'commandResult' in response_json:
            logger.debug('Command result')
            logger.debug(response_json['commandResult'])
            return re.sub('\n$', '', response_json['commandResult'])
        else:
            return None

    def test_remote_file(self, file_path) -> bool:
        return self.run_bash_command(f'[ -f "{file_path}" ] && echo 1 || echo 0') == '1'

    def remote_sha256(self, file_path: str) -> str:
        if self.test_remote_file(file_path):
            res = self.run_bash_command(f'sha256sum {file_path}')
            return re.sub(' .+$', '', res)

    def local_sha256(self, file) -> str:
        return hashlib.sha256(file.decode('utf-8').encode('utf-8')).hexdigest()

    def update_management_cert(self, cert: bytes, key: bytes):

        remote_cert_path = f'/config/httpd/conf/ssl.crt/{self.cert_name}'
        remote_key_path = f'/config/httpd/conf/ssl.key/{self.key_name}'

        if self.local_sha256(cert) == self.remote_sha256(remote_cert_path) \
               and self.local_sha256(key) == self.remote_sha256(remote_key_path):
           logger.info(f'Local certificates matches the remote certificates, no need to update on {self.device}')
           return

        self.upload_file(self.cert_name, cert)
        self.upload_file(self.key_name, key)
        self.run_bash_command(f'mv /var/config/rest/downloads/{self.cert_name} /config/httpd/conf/ssl.crt/')
        self.run_bash_command(f'mv /var/config/rest/downloads/{self.key_name} /config/httpd/conf/ssl.key/')
        self.set_management_cert()

    def get_http_config(self):
        response = self.session.get(f'https://{self.device}/mgmt/tm/sys/httpd')
        return response.json()

    def set_management_cert(self) -> None:

        self.run_bash_command(f'restorecon -RvF /config/httpd/conf/ssl.crt/{self.cert_name}')
        self.run_bash_command(f'restorecon -RvF /config/httpd/conf/ssl.key/{self.key_name}')

        self.session.put(
            f'https://{self.device}/mgmt/tm/sys/httpd',
            json={
                'sslCertfile': f'/config/httpd/conf/ssl.crt/{self.cert_name}',
                'sslCertkeyfile': f'/config/httpd/conf/ssl.key/{self.key_name}'}
        )
        try:
            logger.info('Restarting httpd')
            self.run_bash_command('bigstart restart httpd; killall -9 httpd;bigstart restart httpd;', timeout=5)
        except Exception as e:
            logger.info('Waiting for management interface to restart')
            time.sleep(10)
            httpd_config = self.get_http_config()

            if os.path.basename(httpd_config['sslCertfile']) == self.cert_name \
                    and os.path.basename(httpd_config['sslCertkeyfile']) == self.key_name:
                print('Certificate has been updated and the httpd interface is responding')
            else:
                raise Exception(e)
