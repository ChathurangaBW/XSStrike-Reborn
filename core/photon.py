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

        # Check if the URL contains GET parameters (identified by "=")
        if '=' in target:
            inps = [{'name': name, 'value': value} for name, value in params.items()]
            forms.append({0: {'action': url, 'method': 'get', 'inputs': inps}})
        
        # Request the URL and extract the response
        response = requester(url, params, headers, True, delay, timeout).text
        
        # Analyze the response for vulnerable JS libraries
        retireJs(url, response)

        # DOM Analysis
        if not skipDOM:
            highlighted = dom(response)
            clean_highlighted = ''.join([re.sub(r'^\d+\s+', '', line) for line in highlighted])
            if highlighted and clean_highlighted not in checkedDOMs:
                checkedDOMs.append(clean_highlighted)
                logger.good(f'Potential DOM XSS in: {target}')
        
        # Parse forms and add to the forms list
        forms_parsed = zetanize(response)
        forms.append(forms_parsed)

        # Extract links from the response using anchor tags (<a>)
        matches = re.findall(r'<a.*?href=["\']{0,1}(.*?)["\']', response)
        for link in matches:
            # Ignore file types that we don't need to crawl
            if link.endswith(('.pdf', '.png', '.jpg', '.jpeg', '.xls', '.xml', '.docx', '.doc')):
                continue

            # Handle absolute and relative links
            if link[:4] == 'http':
                if link.startswith(main_url):
                    storage.add(link)
            elif link[:2] == '//':
                if link.split('/')[2].startswith(host):
                    storage.add(schema + link)
            elif link[:1] == '/':
                storage.add(main_url + link)
            else:
                storage.add(main_url + '/' + link)

    # Recursive crawling to specified depth
    try:
        for x in range(level):
            urls = storage - processed  # urls to crawl = all urls - urls that have been crawled
            threadpool = concurrent.futures.ThreadPoolExecutor(max_workers=threadCount)
            futures = (threadpool.submit(rec, url) for url in urls)
            for i in concurrent.futures.as_completed(futures):
                pass
    except KeyboardInterrupt:
        return [forms, processed]

    logger.info(f"Total forms found: {len(forms)}")
    return forms, list(storage)
