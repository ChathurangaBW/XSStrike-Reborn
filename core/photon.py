import re
import concurrent.futures
from urllib.parse import urlparse

from core.dom import dom
from core.log import setup_logger
from core.utils import getUrl, getParams
from core.requester import requester
from core.zetanize import zetanize
from plugins.retireJs import retireJs

logger = setup_logger(__name__)

def photon(seedUrl, headers, level, threadCount, delay, timeout, skipDOM):
    """
    Crawls the target URL and recursively extracts links, forms, and potential XSS vectors.
    
    Args:
        seedUrl (str): The target URL.
        headers (dict): Headers for the request.
        level (int): Crawling depth level.
        threadCount (int): Number of threads for concurrent execution.
        delay (int): Delay between requests.
        timeout (int): Timeout for requests.
        skipDOM (bool): Whether to skip DOM analysis.

    Returns:
        list: List of forms and DOM URLs.
    """
    forms = []  # web forms
    processed = set()  # URLs that have been crawled
    storage = set()  # URLs that belong to the target (in-scope)
    schema = urlparse(seedUrl).scheme  # extract the scheme (http or https)
    host = urlparse(seedUrl).netloc  # extract the host (example.com)
    main_url = schema + '://' + host  # root URL
    storage.add(seedUrl)  # Add initial URL to storage
    checkedDOMs = []  # Track processed DOMs

    def rec(target):
        processed.add(target)
        printableTarget = '/'.join(target.split('/')[3:])
        if len(printableTarget) > 40:
            printableTarget = printableTarget[-40:]
        else:
            printableTarget = (printableTarget + (' ' * (40 - len(printableTarget))))
        logger.run('Parsing %s\r' % printableTarget)
        
        url = getUrl(target, True)
        params = getParams(target, '', True)

        if '=' in target:
            inps = [{'name': name, 'value': value} for name, value in params.items()]
            forms.append({0: {'action': url, 'method': 'get', 'inputs': inps}})
        
        response = requester(url, params, headers, True, delay, timeout).text
        
        # Analyze the response for vulnerable JS libraries
        retireJs(url, response)

        # DOM Analysis
        if not skipDOM:
            highlighted = dom(response)
            clean_highlighted = ''.join([re.sub(r'^\d+\s+', '', line) for line in highlighted])
            if highlighted and clean_highlighted not in checkedDOMs:
                checkedDOMs.append(clean_highlighted)
                logger.good('Potential DOM XSS in: %s' % target)

        # Fix: Call zetanize with only the response
        new_links = zetanize(response)
        for link in new_links:
            if link not in processed and link.startswith(main_url):
                storage.add(link)

    with concurrent.futures.ThreadPoolExecutor(max_workers=threadCount) as executor:
        futures = [executor.submit(rec, url) for url in storage]
        for future in concurrent.futures.as_completed(futures):
            future.result()

    return forms, list(storage)
