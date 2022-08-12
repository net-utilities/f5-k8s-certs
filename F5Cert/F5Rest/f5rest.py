import requests, os, re, hashlib, time, io, urllib3
from typing import Optional
from requests.adapters import HTTPAdapter, Retry
from F5Cert.logger.logger import logger


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
            s = requests.Session()

            body = {
                'username': self.username,
                'password': self.password,
                'loginProviderName': 'tmos'
            }

            logger.debug(f'{self.device}: Getting auth token')
            token_response = s.post(
                f'https://{self.device}/mgmt/shared/authn/login',
                verify=self.verify_ssl,
                auth=(self.username, self.password), json=body) \
                .json()

            token = token_response['token']['token']
            logger.debug(f'{self.device}: Got a token')

            s.headers.update({'X-F5-Auth-Token': token})
            logger.debug(f'{self.device}: Setting SSL validation to {str(self.verify_ssl)}')
            s.verify = self.verify_ssl
            self._session = s
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
            logger.debug(f'{self.device}: Uploading {name} to device')
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

        logger.debug(f'{self.device}: Running bash command {command}')
        response = self.session.post(f'https://{self.device}/mgmt/tm/util/bash',
                                     json=payload, verify=self.verify_ssl, timeout=timeout)

        if response.status_code != 200:
            raise RuntimeError(f'{self.device}: Command {command} failed to run')

        response_json = response.json()

        if 'commandResult' in response_json:
            logger.debug(f'{self.device}: Command result:')
            logger.debug(f'{self.device}: {response_json["commandResult"]}')
            return re.sub('\n$', '', response_json['commandResult'])
        else:
            return None

    def test_remote_file(self, file_path) -> bool:
        logger.debug(f'{self.device}: Testing if {file_path} exists on the device')
        return self.run_bash_command(f'test -f "{file_path}" && echo 1 || echo 0') == '1'

    def remote_sha256(self, file_path: str) -> str:
        logger.debug(f'{self.device}: Getting sha256 hash of {file_path} on the device')
        if self.test_remote_file(file_path):
            res = self.run_bash_command(f'sha256sum {file_path}')
            hash = re.sub(' .+$', '', res)
            logger.debug(f'{self.device}: {file_path} has a sha256 hash of {hash}')
            return re.sub(' .+$', '', res)

    def local_sha256(self, file) -> str:
        logger.debug(f'{self.device}: Getting sha256 hash of the certificate manager certificate')
        hash = hashlib.sha256(file.decode('utf-8').encode('utf-8')).hexdigest()
        logger.debug(f'{self.device}: Certificate has a sha256 hash of {hash}')
        return hash

    def update_management_cert(self, cert: bytes, key: bytes):

        remote_cert_path = f'/config/httpd/conf/ssl.crt/{self.cert_name}'
        remote_key_path = f'/config/httpd/conf/ssl.key/{self.key_name}'

        if self.local_sha256(cert) == self.remote_sha256(remote_cert_path) \
               and self.local_sha256(key) == self.remote_sha256(remote_key_path) \
               and self.httpd_config_is_configured_with_cert():
           logger.info(f'{self.device}: Certificate hashes matches and httpd already configured, no need to update')
           return

        logger.info(f'{self.device}: Certificate hashes does not match, updating')
        self.upload_file(self.cert_name, cert)
        self.upload_file(self.key_name, key)

        logger.debug(f'{self.device}: Moving certificate and key to the destination folder')
        self.run_bash_command(f'mv /var/config/rest/downloads/{self.cert_name} /config/httpd/conf/ssl.crt/')
        self.run_bash_command(f'mv /var/config/rest/downloads/{self.key_name} /config/httpd/conf/ssl.key/')
        self.set_management_cert()

    def get_httpd_config(self):
        logger.debug(f'{self.device}: Getting the httpd config from device:')
        response = self.session.get(f'https://{self.device}/mgmt/tm/sys/httpd')
        data = response.json()
        logger.debug(f'{self.device}: {data}')
        return response.json()

    def httpd_config_is_configured_with_cert(self):
        httpd_config = self.get_httpd_config()
        return os.path.basename(httpd_config['sslCertfile']) == self.cert_name \
                and os.path.basename(httpd_config['sslCertkeyfile']) == self.key_name

    def set_management_cert(self) -> None:

        self.run_bash_command(f'restorecon -RvF /config/httpd/conf/ssl.crt/{self.cert_name}')
        self.run_bash_command(f'restorecon -RvF /config/httpd/conf/ssl.key/{self.key_name}')

        logger.info(f'{self.device}: Configuring the httpd service with the new certificate and key')

        self.session.put(
            f'https://{self.device}/mgmt/tm/sys/httpd',
            json={
                'sslCertfile': f'/config/httpd/conf/ssl.crt/{self.cert_name}',
                'sslCertkeyfile': f'/config/httpd/conf/ssl.key/{self.key_name}'}
        )
        try:
            logger.info(f'{self.device}: Restarting httpd')
            self.run_bash_command('bigstart restart httpd; killall -9 httpd;bigstart restart httpd;', timeout=5)
        except Exception as e:
            logger.info(f'{self.device}: Waiting for management interface to restart')

        time.sleep(15)
        try:
            config_ok = self.httpd_config_is_configured_with_cert()
        except Exception as e:
            logger.info(f'{self.device}: httpd service is not ready, waiting 15 seconds before retrying')
            time.sleep(15)
            config_ok = self.httpd_config_is_configured_with_cert()

        if not config_ok:
            raise Exception(e)
        logger.info(f'{self.device}: Certificate and key has been updated successfully')
