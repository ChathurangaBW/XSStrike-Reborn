import random
import requests
import time
from urllib3.exceptions import ProtocolError
import warnings

import core.config
from core.utils import converter, getVar
from core.log import setup_logger

logger = setup_logger(__name__)
warnings.filterwarnings('ignore')

def requester(url, data, headers, GET, delay, timeout, retries=3, backoff_factor=2):
    """
    Sends HTTP requests with retries and user-agent randomization.
    """
    if getVar('jsonData'):
        data = converter(data)
    elif getVar('path'):
        url = converter(data, url)
        data = []
        GET = True

    time.sleep(delay)
    user_agents = ['Mozilla/5.0', 'Mozilla/5.0', 'Mozilla/5.0']
    if 'User-Agent' not in headers or headers['User-Agent'] == '$':
        headers['User-Agent'] = random.choice(user_agents)

    logger.debug(f"Requester URL: {url}")
    for attempt in range(retries):
        try:
            if GET:
                response = requests.get(url, params=data, headers=headers, timeout=timeout, verify=False, proxies=core.config.proxies)
            elif getVar('jsonData'):
                response = requests.post(url, json=data, headers=headers, timeout=timeout, verify=False, proxies=core.config.proxies)
            else:
                response = requests.post(url, data=data, headers=headers, timeout=timeout, verify=False, proxies=core.config.proxies)

            return response
        except ProtocolError:
            logger.warning("WAF detected. Retrying after 10 minutes.")
            time.sleep(600)
        except requests.exceptions.RequestException as e:
            logger.warning(f"Request failed (attempt {attempt + 1}/{retries}): {e}. Retrying after {backoff_factor ** attempt} seconds.")
            time.sleep(backoff_factor ** attempt)

    logger.error(f"Failed to connect to {url} after {retries} retries.")
    return requests.Response()
