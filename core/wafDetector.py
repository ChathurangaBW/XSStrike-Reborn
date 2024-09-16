import json
import re
import sys
from core.requester import requester
from core.log import setup_logger

logger = setup_logger(__name__)

def wafDetector(url, params, headers, GET, delay, timeout, retries=3):
    """
    Detects the presence of a Web Application Firewall (WAF) by sending a noisy payload
    and analyzing the response for known WAF signatures.

    Args:
        url (str): The target URL.
        params (dict): Parameters to include in the request.
        headers (dict): HTTP headers for the request.
        GET (bool): Whether to send a GET request.
        delay (int): Delay before sending the request.
        timeout (int): Request timeout in seconds.
        retries (int): Number of retries for the request.

    Returns:
        str or None: The name of the detected WAF, or None if no WAF is detected.
    """
    try:
        with open(sys.path[0] + '/db/wafSignatures.json', 'r') as file:
            wafSignatures = json.load(file)
    except FileNotFoundError:
        logger.error("WAF signatures file not found.")
        return None
    except json.JSONDecodeError as e:
        logger.error(f"Error parsing WAF signatures: {e}")
        return None

    # Inject a noisy XSS payload to provoke the WAF
    noise = '<script>alert("XSS")</script>'
    params['xss'] = noise

    # Send the request with retries
    response = None
    for attempt in range(retries):
        try:
            response = requester(url, params, headers, GET, delay, timeout)
            if response:
                break
        except Exception as e:
            logger.warning(f"Failed to send request (attempt {attempt + 1}/{retries}): {e}")

    if not response:
        logger.error("Failed to connect to the target after multiple retries.")
        return None

    page = response.text
    code = str(response.status_code)
    headers_response = str(response.headers)

    logger.debug(f"WAF Detector response code: {code}")
    logger.debug_json("WAF Detector response headers:", response.headers)

    # Analyze response against known WAF signatures
    if int(code) >= 400:
        bestMatch = [0, None]  # Initialize with zero score
        for wafName, wafSignature in wafSignatures.items():
            score = 0
            pageSign = wafSignature['page']
            codeSign = wafSignature['code']
            headersSign = wafSignature['headers']

            # Check if the WAF signature matches the page content
            if pageSign and re.search(pageSign, page, re.I):
                score += 1
            # Check if the status code matches the WAF signature
            if codeSign and re.search(codeSign, code, re.I):
                score += 0.5  # Less weight for status codes since they are less reliable
            # Check if the headers match the WAF signature
            if headersSign and re.search(headersSign, headers_response, re.I):
                score += 1

            # Update the best match based on the score
            if score > bestMatch[0]:
                bestMatch = [score, wafName]

        if bestMatch[1]:
            logger.info(f"WAF Detected: {bestMatch[1]}")
            return bestMatch[1]
        else:
            logger.info("No WAF detected.")
            return None
    else:
        logger.info("No suspicious response indicating WAF was detected.")
        return None
