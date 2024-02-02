import io
import json
import os
import sys
import time
import yaml
import threading
import socket
import hmac
import base64
import hashlib
from typing import List
from loguru import logger
from urllib import parse
import urllib.request
from urllib.error import HTTPError, URLError

CONFIGURATIONS = "configurations"
NOTIFICATION_ID = "notificationId"
NAMESPACE_NAME = "namespaceName"
RELEASE_KEY = "releaseKey"
CONTENT = "content"


class ApolloClient(object):

    def __init__(self,
                 app_id='',
                 config_url='http://localhost:8080',
                 cluster='default',
                 secret='',
                 env='DEV',
                 need_hot_update=True,
                 change_listener=None,
                 client_ip=None,
                 log_level='INFO',
                 notification_map=None,
                 cache_path=None):

        # Set up the logger
        logger.remove()
        logger.add(sys.stdout, level=log_level)

        # Set attributes
        self.app_id = self.config_setter("APPID", app_id)
        self.cluster = self.config_setter("IDC", cluster)
        self.secret = self.config_setter("APOLLO_ACCESS_KEY_SECRET", secret)
        self.env = env
        self.client_ip = self.config_setter("CLIENT_IP", client_ip) or self.init_ip()
        self.cache_path = self.config_setter("APOLLO_CACHE_PATH", cache_path) or self.default_cache_path()
        self.apollo_meta = os.environ.get(f"{env}_META") or self.config_setter("APOLLO_META", config_url)

        logger.info("APOLLO_META: {}", self.apollo_meta)

        # Thread management
        self.need_hot_update = need_hot_update
        self.change_listener = change_listener
        self._notification_map = notification_map or {'application': -1}
        self.pull_timeout = 75
        self.cycle_time = 2
        self.stopping = False
        self.last_release_key = None
        self._cache = {}
        self.no_key_cache = {}
        self.hash_cache = {}

        # Initialize cache and start threads
        self._init_load_all_namespaces()
        if self.need_hot_update:
            self._start_hot_update()

        heartbeat = threading.Thread(target=self._heart_beat, daemon=True)
        heartbeat.start()

    @staticmethod
    def config_setter(env_name, custom_value):
        return os.environ.get(env_name) or custom_value

    @staticmethod
    def init_ip():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect(('8.8.8.8', 53))
                ip = s.getsockname()[0]
            finally:
                s.close()
        except socket.error as err:
            logger.error(f"Unable to get local IP: {err}")
            ip = "127.0.0.1"
        return ip

    @staticmethod
    def default_cache_path():
        path = os.path.join('tmp', 'apollo', "cache")
        os.makedirs(path, exist_ok=True)
        return path

    def _init_load_all_namespaces(self):
        failed_namespaces = []
        for namespace in self._notification_map:
            try:
                namespace_data = self.get_json_from_net(namespace)
                if namespace_data:
                    self._cache[namespace] = namespace_data
                else:
                    failed_namespaces.append(namespace)
            except Exception as ex:
                logger.error(f"Failed to load data for namespace '{namespace}': {ex}")
                failed_namespaces.append(namespace)

        if failed_namespaces:
            logger.warning(f"Could not initialize data for namespaces: {failed_namespaces}")

    @staticmethod
    def _http_request(url, timeout, headers=None):
        headers = headers or {}
        request = urllib.request.Request(url, headers=headers)

        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                body = response.read().decode("utf-8")
                return response.code, body
        except HTTPError as e:
            return e.code, None
        except URLError as e:
            logger.error(f"Failed to make a request to {url}: {e.reason}")
            return None, None
        except Exception as e:
            logger.exception(f"Unexpected error during HTTP request to {url}: {e}")
            raise

    @staticmethod
    def signature(timestamp, uri, secret):
        string_to_sign = f'{timestamp}\n{uri}'
        hmac_code = hmac.new(secret.encode(), string_to_sign.encode(), hashlib.sha1).digest()
        return base64.b64encode(hmac_code).decode()

    @staticmethod
    def _handle_resp_body(data):
        data = data.get(CONFIGURATIONS)
        if data is None:
            logger.error(f"'{CONFIGURATIONS}' key not found in data.")
            return data

        content = data.get(CONTENT)
        if content is not None:
            data_bytes = content.encode('utf-8')
            try:
                return yaml.load(io.BytesIO(data_bytes), Loader=yaml.SafeLoader)
            except yaml.YAMLError as e:
                logger.error(f"Failed to load YAML content: {e}")
                return None

        return data

    @staticmethod
    def _url_encode_wrapper(params):
        return parse.urlencode(params)

    @staticmethod
    def _no_key_cache_key(ns, key):
        return "{}{}{}".format(ns, len(ns), key)

    def get_value_from_dict(self, ns_cache, key):
        if not ns_cache:
            return None

        kv_data = ns_cache.get(CONFIGURATIONS)
        if kv_data is None:
            return None
        value = kv_data.get(key)

        if value is not None:
            return value

        sub_keys = key.split(".")
        return self.get_value_in_yaml(kv_data, sub_keys)

    @staticmethod
    def get_value_in_yaml(kv_data, args: List):
        for arg in args:
            if not isinstance(kv_data, dict) or arg not in kv_data:
                return None
            kv_data = kv_data[arg]

        return kv_data

    def get_value_from_local(self, key):
        for namespace in self._notification_map:
            namespace_cache = self._cache.get(namespace)
            if namespace_cache is None:
                continue
            try:
                val = self.get_value_from_dict(namespace_cache, key)
                if val is not None:
                    return val
            except KeyError as e:
                logger.error(f"can not found key:'{key}' in '{namespace}' {e}")
            except Exception as e:
                logger.error(f"namespace: '{namespace}', key: '{key}': {e}")

        return None

    def get_json_from_net(self, namespace='application'):
        url = f'{self.apollo_meta}/configs/{self.app_id}/{self.cluster}/{namespace}?releaseKey=&ip={self.client_ip}'
        try:
            code, body = self._http_request(url, timeout=5, headers=self._sign_headers(url))
            if code == 200:
                data = json.loads(body)
                data = self._handle_resp_body(data)
                return {CONFIGURATIONS: data}
            else:
                logger.warning(f'Failed to fetch configuration. Status code: {code}')
                return None
        except Exception as e:
            logger.exception('An error occurred while fetching configuration from the network: ', e)
            return None

    def _get_value_from_sources(self, namespace, key):
        namespace_data = self.get_json_from_net(namespace)
        val = self.get_value_from_dict(namespace_data, key)
        if val is not None:
            self._update_cache_and_file(namespace_data, namespace)
            return val

        namespace_cache = self._get_local_cache(namespace)
        val = self.get_value_from_dict(namespace_cache, key)
        if val is not None:
            self._update_cache_and_file(namespace_cache, namespace)
            return val

        self._set_local_cache_none(namespace, key)
        return None

    def get_value(self, key, default_val=None, namespace='application'):
        namespace_cache = self._cache.get(namespace)
        val = self.get_value_from_dict(namespace_cache, key)
        if val is not None:
            return val

        no_key = self._no_key_cache_key(namespace, key)
        if no_key in self.no_key_cache:
            return default_val

        val = self._get_value_from_sources(namespace, key)
        return val if val is not None else default_val

    def _set_local_cache_none(self, namespace, key):
        no_key = self._no_key_cache_key(namespace, key)
        self.no_key_cache[no_key] = key

    def _start_hot_update(self):
        self._long_poll_thread = threading.Thread(target=self._listener, daemon=True)
        self._long_poll_thread.start()

    def stop(self):
        self.stopping = True
        logger.info("Stopping listener...")

    def _call_listener(self, namespace, old_kv, new_kv):
        if self.change_listener is None:
            return

        old_kv = old_kv or {}
        new_kv = new_kv or {}

        all_keys = set(old_kv) | set(new_kv)

        try:
            for key in all_keys:
                new_value = new_kv.get(key)
                old_value = old_kv.get(key)
                if new_value != old_value:
                    if new_value is None:
                        self.change_listener("delete", namespace, key, old_value)
                    elif old_value is None:
                        self.change_listener("add", namespace, key, new_value)
                    else:
                        self.change_listener("update", namespace, key, new_value)
        except Exception as e:
            logger.error(f"Error calling change listener for namespace '{namespace}': {e}")

    def _update_cache_and_file(self, namespace_data, namespace='application'):
        self._cache[namespace] = namespace_data

        new_string = json.dumps(namespace_data, ensure_ascii=False)
        new_hash = hashlib.md5(new_string.encode('utf-8')).hexdigest()

        old_hash = self.hash_cache.get(namespace)
        if old_hash != new_hash:
            file_path = os.path.join(self.cache_path, f'{self.app_id}_configuration_{namespace}.txt')
            try:
                with open(file_path, 'w') as f:
                    f.write(new_string)
                self.hash_cache[namespace] = new_hash
                logger.debug(f"Updated namespace '{namespace}' data and hash.")
            except IOError as e:
                logger.error(f"Error updating file '{file_path}': {e}")

    def _get_local_cache(self, namespace='application'):
        cache_file_path = os.path.join(self.cache_path, '%s_configuration_%s.txt' % (self.app_id, namespace))
        if os.path.isfile(cache_file_path):
            with open(cache_file_path, 'r') as f:
                result = json.loads(f.readline())
            return result
        return {}

    def _long_poll(self):
        notifications = [
            {
                NAMESPACE_NAME: key,
                NOTIFICATION_ID: namespace_data.get(NOTIFICATION_ID, -1)
            }
            for key, namespace_data in self._cache.items()
        ]

        if not notifications:
            logger.info("_long_poll: No notifications to poll.")
            return

        try:
            url = f'{self.apollo_meta}/notifications/v2'
            params = {
                'appId': self.app_id,
                'cluster': self.cluster,
                'notifications': json.dumps(notifications, ensure_ascii=False)
            }
            param_str = self._url_encode_wrapper(params)
            url = url + '?' + param_str
            http_code, body = self._http_request(url, self.pull_timeout,
                                                 headers=self._sign_headers(url))
            if http_code == 304:
                logger.debug('No change detected by long poll.')
                return

            if http_code == 200:
                logger.debug(f"Received update notification: {body}")
                data = json.loads(body)
                for entry in data:
                    namespace = entry[NAMESPACE_NAME]
                    n_id = entry[NOTIFICATION_ID]
                    logger.info(f"{namespace} has changes: notificationId={n_id}")
                    self._get_net_and_set_local(namespace, n_id, call_change=True)
                    break

            else:
                logger.warning(f"Long poll received unexpected HTTP status code: {http_code}")

        except Exception as e:
            logger.exception("Long polling failed with an exception.", exc_info=e)

    def _get_net_and_set_local(self, namespace, n_id, call_change=False):
        try:
            namespace_data = self.get_json_from_net(namespace)
            if namespace_data is None:
                logger.error(f"can not get data from {namespace}")
                return

            namespace_data[NOTIFICATION_ID] = n_id

            old_namespace = self._cache.get(namespace, {})
            self._update_cache_and_file(namespace_data, namespace)

            if self.change_listener is not None and call_change:
                old_kv = old_namespace.get(CONFIGURATIONS, {})
                new_kv = namespace_data.get(CONFIGURATIONS, {})
                self._call_listener(namespace, old_kv, new_kv)

        except Exception as e:
            logger.error(f"_get_net_and_set_local error: {e}")

    def _listener(self):
        logger.info('start long_poll')
        while not self.stopping:
            self._long_poll()
            time.sleep(self.cycle_time)
        logger.info("stopped, long_poll")

    def _sign_headers(self, url):
        headers = {}
        if self.secret == '':
            return headers
        uri = url[len(self.apollo_meta):len(url)]
        time_unix_now = str(int(round(time.time() * 1000)))
        headers['Authorization'] = 'Apollo ' + self.app_id + ':' + self.signature(time_unix_now, uri, self.secret)
        headers['Timestamp'] = time_unix_now
        return headers

    def _heart_beat(self):
        while not self.stopping:
            for namespace in self._notification_map:
                self._do_heart_beat(namespace)
            time.sleep(60 * 10)

    def _do_heart_beat(self, namespace):
        url = '{}/configs/{}/{}/{}?ip={}'.format(self.apollo_meta, self.app_id, self.cluster, namespace,
                                                 self.client_ip)
        try:
            code, body = self._http_request(url, timeout=3, headers=self._sign_headers(url))
            if code == 200:
                data = json.loads(body)
                if self.last_release_key == data["releaseKey"]:
                    return None
                self.last_release_key = data["releaseKey"]
                data = self._handle_resp_body(data)
                logger.info("_do_heartBeat")
                self._update_cache_and_file(data, namespace)
            else:
                return None
        except Exception as e:
            logger.error(e)
            return None


if __name__ == '__main__':
    app_id = 'demo-service'
    config_url = 'http://127.0.0.1:8080'
    cluster = 'default'
    secret = ''
    env = 'DEV'

    client = ApolloClient(app_id=app_id, config_url=config_url, cluster=cluster, secret=secret, env=env)
    for i in range(100):
        lm_API_KEY = client.get_value("lm_API_KEY")
        print(lm_API_KEY)
        time.sleep(1)
