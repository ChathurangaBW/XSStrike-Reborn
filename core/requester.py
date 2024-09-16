import random
import requests
import time
from urllib3.exceptions import ProtocolError
import warnings

import core.config
from core.utils import converter, getVar
from core.log import setup_logger

logger = setup_logger(__name__)

# Disable SSL-related warnings
warnings.filterwarnings('ignore')

def requester(url, data, headers, GET, delay, timeout, retries=3, backoff_factor=2):
    """
    Sends HTTP requests with improved error handling, retries, and dynamic user-agent support.

    Args:
        url (str): The target URL.
        data (dict): Data to be sent with the request.
        headers (dict): HTTP headers for the request.
        GET (bool): If True, send a GET request; otherwise, send POST.
        delay (int): Time delay between requests.
        timeout (int): Timeout duration for the request.
        retries (int): Number of retries in case of failure.
        backoff_factor (int): Delay between retries increases with this factor.
    
    Returns:
        requests.Response: HTTP response object or empty response if failure occurs.
    """
    
    # Prepare the data or URL based on the configuration
    if getVar('jsonData'):
        data = converter(data)
    elif getVar('path'):
        url = converter(data, url)
        data = []
        GET = True
    
    # Add a delay before sending the request
    time.sleep(delay)

    # List of random user-agents to bypass basic WAFs
    user_agents = [
        'Mozilla/5.0 (X11; Linux i686; rv:60.0) Gecko/20100101 Firefox/60.0',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36 OPR/43.0.2442.991'
    ]

    # Set or randomize the User-Agent header
    if 'User-Agent' not in headers or headers['User-Agent'] == '$':
        headers['User-Agent'] = random.choice(user_agents)

    # Log the request details
    logger.debug(f"Requester URL: {url}")
    logger.debug(f"Requester GET method: {GET}")
    logger.debug_json("Requester data:", data)
    logger.debug_json("Requester headers:", headers)

    # Retry logic with exponential backoff
    for attempt in range(retries):
        try:
            # Send GET or POST request based on the configuration
            if GET:
                response = requests.get(url, params=data, headers=headers, timeout=timeout, verify=False, proxies=core.config.proxies)
            elif getVar('jsonData'):
                response = requests.post(url, json=data, headers=headers, timeout=timeout, verify=False, proxies=core.config.proxies)
            else:
                response = requests.post(url, data=data, headers=headers, timeout=timeout, verify=False, proxies=core.config.proxies)
            
            # Return the response if successful
            return response
        
        except ProtocolError:
            # Handle WAF dropping the connection
            logger.warning("WAF detected. Retrying after 10 minutes.")
            time.sleep(600)  # 10-minute delay
        
        except requests.exceptions.RequestException as e:
            # Log the exception and apply exponential backoff
            logger.warning(f"Request failed (attempt {attempt + 1}/{retries}): {e}. Retrying after {backoff_factor ** attempt} seconds.")
            time.sleep(backoff_factor ** attempt)
    
    # If all retries fail, log the failure and return an empty response
    logger.error(f"Failed to connect to {url} after {retries} retries.")
    return requests.Response()
