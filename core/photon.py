from urllib.parse import urljoin, urlparse
import concurrent.futures
from core.utils import getParams, randomUpper, handle_anchor
from core.requester import requester
from core.log import setup_logger

logger = setup_logger(__name__)

def photon(url, headers, level, threads, delay, timeout, skipDOM):
    """
    Crawls the target URL and recursively extracts links, forms, and potential XSS vectors.

    Args:
        url (str): The target URL.
        headers (dict): Headers for the request.
        level (int): Crawling depth level.
        threads (int): Number of threads for concurrent execution.
        delay (int): Delay between requests.
        timeout (int): Timeout for requests.
        skipDOM (bool): Whether to skip DOM analysis.

    Returns:
        list: List of forms and DOM URLs.
    """
    scheme = urlparse(url).scheme
    host = urlparse(url).netloc
    main_url = scheme + '://' + host
    forms = []
    dom_urls = set()

    # Crawl the initial target page
    crawlingResult = requester(url, {}, headers, True, delay, timeout)
    if not crawlingResult:
        return forms, dom_urls

    forms += getParams(url, crawlingResult.text, True)
    anchors = set(re.findall(r'<a.*?href=[\'"](.*?)[\'"]', crawlingResult.text, re.I))

    # Handle relative and absolute anchors
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [
            executor.submit(requester, handle_anchor(url, anchor), {}, headers, True, delay, timeout)
            for anchor in anchors
        ]

        for future in concurrent.futures.as_completed(futures):
            response = future.result()
            if response and url in response.url:
                forms += getParams(url, response.text, True)
                dom_urls.add(response.url)

    return forms, list(dom_urls)
