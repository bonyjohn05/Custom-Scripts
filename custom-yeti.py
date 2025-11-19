#!/var/ossec/framework/python/bin/python3
import json
import os
import re
import sys
import requests
from requests.exceptions import Timeout
from socket import AF_UNIX, SOCK_DGRAM, socket

# Exit error codes
ERR_NO_REQUEST_MODULE = 1
ERR_BAD_ARGUMENTS = 2
ERR_BAD_MD5_SUM = 3
ERR_NO_RESPONSE_YETI = 4
ERR_SOCKET_OPERATION = 5
ERR_FILE_NOT_FOUND = 6
ERR_INVALID_JSON = 7

# Global vars
debug_enabled = True
timeout = 10
retries = 3
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
json_alert = {}

# Log and socket path
LOG_FILE = f'{pwd}/logs/integrations.log'
SOCKET_ADDR = f'{pwd}/queue/sockets/queue'

# Argument indexes for Wazuh integration
# argv[0] = script
# argv[1] = alert file
# argv[2] = api_key       (from <api_key> in ossec.conf)
ALERT_INDEX = 1
APIKEY_INDEX = 2
TIMEOUT_INDEX = 6
RETRIES_INDEX = 7

# Yeti instance (your host) – IMPORTANT: set this to your real IP/URL
YETI_INSTANCE = 'http://<yeti-server-IP>'


def debug(msg: str) -> None:
    """Log the message in the log file if debug flag is enabled."""
    if debug_enabled:
        print(msg)
        with open(LOG_FILE, 'a') as f:
            f.write(msg + '\n')


def main(args):
    global timeout
    global retries

    try:
        if len(args) < 3:
            msg = '# Error: Wrong arguments\n'
            with open(LOG_FILE, 'a') as f:
                f.write(msg)
            debug('# Error: Exiting, bad arguments. Inputted: %s' % str(args))
            sys.exit(ERR_BAD_ARGUMENTS)

        # Optional timeout / retries if you ever add extra args
        if len(args) > TIMEOUT_INDEX:
            try:
                timeout_val = int(args[TIMEOUT_INDEX])
                timeout = timeout_val
            except ValueError:
                debug(f'# Warning: Invalid timeout value "{args[TIMEOUT_INDEX]}", using default {timeout}')

        if len(args) > RETRIES_INDEX:
            try:
                retries_val = int(args[RETRIES_INDEX])
                retries = retries_val
            except ValueError:
                debug(f'# Warning: Invalid retries value "{args[RETRIES_INDEX]}", using default {retries}')

        try:
            apikey: str = args[APIKEY_INDEX]
        except IndexError:
            debug('# Error: API key argument not found at expected index')
            sys.exit(ERR_BAD_ARGUMENTS)

        debug(f'# API key from args (first 8 chars): {apikey[:8]}...')

        access_token = getAccessToken(apikey)
        process_args(args, access_token)

    except Exception as e:
        debug(f'# Unhandled exception in main: {e}')
        raise


def getAccessToken(apikey: str) -> str:
    """Exchange API key for a JWT access token."""
    url = f"{YETI_INSTANCE}/api/v2/auth/api-token"
    headers = {"x-yeti-apikey": apikey}
    try:
        debug(f'# Requesting access token from {url}')
        response = requests.post(url, headers=headers, timeout=timeout)
        if response.status_code == 404:
            debug(f"# Error: Token endpoint not found at {url}. Check YETI_INSTANCE or API path.")
            sys.exit(1)

        response.raise_for_status()
        access_token = response.json().get("access_token")
        if not access_token:
            raise ValueError("Access token missing in the response.")
        debug('# Access token successfully obtained from Yeti')
        return access_token
    except requests.exceptions.RequestException as e:
        debug(f"Error obtaining access token from API: {e}")
        sys.exit(1)


def process_args(args, access_token: str) -> None:
    """Load alert JSON and route to proper handler."""
    debug('# Running Yeti script')

    alert_file_location: str = args[ALERT_INDEX]
    json_alert = get_json_alert(alert_file_location)
    debug(f"# Opening alert file at '{alert_file_location}' with '{json_alert}'")

    if json_alert.get('data') and json_alert['data'].get('srcip'):
        debug('# Detected an SSH-related alert (data.srcip present)')
        msg = request_ssh_info(json_alert, access_token)

    elif json_alert.get('syscheck') and json_alert['syscheck'].get('md5_after'):
        debug('# Detected a file integrity alert (syscheck.md5_after present)')
        msg = request_md5_info(json_alert, access_token)

    else:
        debug('# Alert does not match known types (SSH or MD5). Skipping processing.')
        return None

    if msg:
        agent = json_alert.get('agent', {})
        send_msg(msg, agent)
    else:
        debug('# No valid message generated. Skipping sending.')


def get_json_alert(file_location: str) -> any:
    """Read JSON alert object from file."""
    try:
        with open(file_location) as alert_file:
            return json.load(alert_file)
    except FileNotFoundError:
        debug("# JSON file for alert %s doesn't exist" % file_location)
        sys.exit(ERR_FILE_NOT_FOUND)
    except json.decoder.JSONDecodeError as e:
        debug('Failed getting JSON alert. Error: %s' % e)
        sys.exit(ERR_INVALID_JSON)


def normalize_observables(yeti_response_data):
    """
    Normalize Yeti responses into a list of observables.

    Handles:
    - plain list: [ {...}, {...} ]
    - dict with 'observables': { "observables": [ ... ], "total": N }
    - dict with 'items': { "items": [ ... ], ... }
    """
    if isinstance(yeti_response_data, list):
        return yeti_response_data
    if isinstance(yeti_response_data, dict):
        if 'observables' in yeti_response_data:
            return yeti_response_data.get('observables', [])
        if 'items' in yeti_response_data:
            return yeti_response_data.get('items', [])
    return []


def request_ssh_info(alert: any, access_token: str):
    """Build output for SSH/IP alerts."""
    alert_output = {'yeti': {}, 'integration': 'yeti'}

    data = alert.get('data', {})
    src_ip = data.get('srcip')

    if not isinstance(src_ip, str):
        debug(f"# Invalid src_ip: '{src_ip}' is not a string")
        return None

    octets = src_ip.split('.')
    if len(octets) != 4 or not all(octet.isdigit() for octet in octets):
        debug(f"# Invalid src_ip format: '{src_ip}'")
        return None

    octets = list(map(int, octets))
    if (
        any(octet < 0 or octet > 255 for octet in octets) or
        octets[0] in [10, 127] or
        (octets[0] == 192 and octets[1] == 168) or
        (octets[0] == 172 and 16 <= octets[1] <= 31) or
        octets[0] >= 240
    ):
        debug(f"# Invalid src_ip: '{src_ip}' is private, reserved, or out of range")
        return None

    yeti_response_data = request_info_from_api(alert_output, access_token, src_ip)
    if not yeti_response_data:
        debug("No data returned from the Yeti API.")
        return None

    observables = normalize_observables(yeti_response_data)

    alert_output['yeti']['source'] = {
        'alert_id': alert.get('id'),
        'src_ip': data.get('srcip'),
        'src_port': data.get('srcport'),
        'dst_user': data.get('dstuser'),
    }

    for observable in observables:
        if not isinstance(observable, dict):
            debug(f"Invalid observable format: {observable}")
            continue

        value = observable.get("value")
        contexts = observable.get("context", []) or observable.get("contexts", [])

        for context_entry in contexts:
            if context_entry.get("source") == "AlienVaultIPReputation":
                if value == src_ip:
                    alert_output['yeti'].update(
                        {
                            'info': {
                                'country_code': context_entry.get("country"),
                                'threat': context_entry.get("threat"),
                                'reliability': context_entry.get("reliability"),
                                'risk': context_entry.get("risk"),
                                'source': "AlienVaultIPReputation",
                            }
                        }
                    )
                    return alert_output

    debug(f"No matching IP address '{src_ip}' found in YETI API for source 'AlienVaultIPReputation'.")
    return None


def request_md5_info(alert: any, access_token: str):
    """Build output for MD5/file alerts."""
    alert_output = {'yeti': {}, 'integration': 'yeti'}

    syscheck = alert.get('syscheck', {})
    md5_hash = syscheck.get('md5_after')

    if not isinstance(md5_hash, str) or len(
        re.findall(r'\b([a-f\d]{32}|[A-F\d]{32})\b', md5_hash)
    ) != 1:
        debug(f"# Invalid md5_after value: '{md5_hash}'")
        return None

    yeti_response_data = request_info_from_api(alert_output, access_token, md5_hash)
    if not yeti_response_data:
        debug("No data returned from the Yeti API.")
        return None

    observables = normalize_observables(yeti_response_data)

    alert_output['yeti']['source'] = {
        'alert_id': alert.get('id'),
        'file': syscheck.get('path'),
        'md5': syscheck.get('md5_after'),
        'sha1': syscheck.get('sha1_after'),
    }

    for observable in observables:
        if not isinstance(observable, dict):
            debug(f"Invalid observable format: {observable}")
            continue

        value = observable.get("value")
        contexts = observable.get("context", []) or observable.get("contexts", [])

        for context_entry in contexts:
            if context_entry.get("source") == "AbuseCHMalwareBazaaar":
                if value == md5_hash:
                    alert_output['yeti'].update(
                        {
                            'info': {
                                'country_code': context_entry.get("country"),
                                'threat': context_entry.get("threat"),
                                'reliability': context_entry.get("reliability"),
                                'risk': context_entry.get("risk"),
                                'source': "AbuseCHMalwareBazaaar",
                            }
                        }
                    )
                    return alert_output

    debug(f"No matching hash '{md5_hash}' found in YETI API for source 'AbuseCHMalwareBazaaar'.")
    return None


def request_info_from_api(alert_output, access_token, observable_value):
    """Request information from Yeti API (GET /observables/?value=...)."""
    for attempt in range(retries + 1):
        try:
            yeti_response_data = query_api(observable_value, access_token)
            return yeti_response_data
        except Timeout:
            debug('# Error: Request timed out. Remaining retries: %s' % (retries - attempt))
            continue
        except Exception as e:
            debug(str(e))
            sys.exit(ERR_NO_RESPONSE_YETI)

    debug('# Error: Request timed out and maximum number of retries was exceeded')
    alert_output['yeti']['error'] = 408
    alert_output['yeti']['description'] = 'Error: API request timed out'
    send_msg(alert_output)
    sys.exit(ERR_NO_RESPONSE_YETI)


def query_api(observable_value, access_token: str) -> any:
    """Query Yeti using GET /api/v2/observables/?value=<observable>."""
    url = f'{YETI_INSTANCE}/api/v2/observables/?value={observable_value}'
    headers = {
        "Authorization": f"Bearer {access_token}"
    }
    debug(f'# Querying Yeti API: {url}')
    response = requests.get(url, headers=headers, timeout=timeout)

    if response.status_code == 200:
        try:
            return response.json()
        except json.JSONDecodeError as e:
            debug(f'# Error decoding JSON from Yeti: {e}')
            return None

    if response.status_code == 404:
        debug(f"# Yeti returned 404 for value '{observable_value}' (no observable found).")
        return None

    handle_api_error(response.status_code)


def handle_api_error(status_code):
    """Handle errors from the Yeti API."""
    alert_output = {}
    alert_output['yeti'] = {}
    alert_output['integration'] = 'yeti'

    if status_code == 401:
        alert_output['yeti']['error'] = status_code
        alert_output['yeti']['description'] = 'Error: Unauthorized. Check your API key.'
        send_msg(alert_output)
        raise Exception('# Error: Yeti credentials, required privileges error')
    elif status_code == 404:
        alert_output['yeti']['error'] = status_code
        alert_output['yeti']['description'] = 'Error: Resource not found.'
    elif status_code == 500:
        alert_output['yeti']['error'] = status_code
        alert_output['yeti']['description'] = 'Error: Internal server error.'
    else:
        alert_output['yeti']['error'] = status_code
        alert_output['yeti']['description'] = 'Error: API request failed.'

    send_msg(alert_output)
    raise Exception(f'# Error: Yeti API request failed with status code {status_code}')


def send_msg(msg: any, agent: any = None) -> None:
    """Send message to Wazuh analysisd socket."""
    if not agent or agent.get('id') == '000':
        string = '1:yeti:{0}'.format(json.dumps(msg))
    else:
        location = '[{0}] ({1}) {2}'.format(
            agent.get('id'),
            agent.get('name'),
            agent.get('ip') if 'ip' in agent else 'any'
        )
        location = location.replace('|', '||').replace(':', '|:')
        string = '1:{0}->yeti:{1}'.format(location, json.dumps(msg))

    debug('# Request result from Yeti server: %s' % string)
    try:
        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.connect(SOCKET_ADDR)
        sock.send(string.encode())
        sock.close()
    except FileNotFoundError:
        debug('# Error: Unable to open socket connection at %s' % SOCKET_ADDR)
        sys.exit(ERR_SOCKET_OPERATION)


if __name__ == '__main__':
    main(sys.argv)
