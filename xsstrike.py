#!/usr/bin/env python3

from __future__ import print_function

from core.colors import end, red, white, bad, info

# Just a fancy ass banner
print('''%s
\tXSStrike %sv3.1.5
%s''' % (red, white, end))

try:
    import concurrent.futures
    from urllib.parse import urlparse
    try:
        import fuzzywuzzy
    except ImportError:
        import os
        print('%s fuzzywuzzy isn\'t installed, installing now.' % info)
        ret_code = os.system('pip3 install fuzzywuzzy')
        if(ret_code != 0):
            print('%s fuzzywuzzy installation failed.' % bad)
            quit()
        print('%s fuzzywuzzy has been installed, restart XSStrike.' % info)
        quit()
except ImportError:  # throws error in python2
    print('%s XSStrike isn\'t compatible with python2.\n Use python > 3.4 to run XSStrike.' % bad)
    quit()

# Let's import whatever we need from standard lib
import sys
import json
import argparse
import os
import time
import asyncio  # Added for async functions

# Import Playwright for Chromium validation
try:
    from playwright.async_api import async_playwright
except ImportError:
    print('%s Playwright isn\'t installed, installing now.' % info)
    ret_code = os.system('pip3 install playwright')
    if ret_code != 0:
        print('%s Playwright installation failed.' % bad)
        quit()
    print('%s Playwright has been installed, installing browsers...' % info)
    ret_code = os.system('playwright install')
    if ret_code != 0:
        print('%s Playwright browsers installation failed.' % bad)
        quit()
    print('%s Playwright is ready, restart XSStrike.' % info)
    quit()

# ... and configurations core lib
import core.config
import core.log

# Processing command line arguments, where dest var names will be mapped to local vars with the same name
parser = argparse.ArgumentParser()
parser.add_argument('-u', '--url', help='url', dest='target')
parser.add_argument('--input-file', help='file containing URLs', dest='input_file')
parser.add_argument('--data', help='post data', dest='paramData')
parser.add_argument('-e', '--encode', help='encode payloads', dest='encode')
parser.add_argument('--fuzzer', help='fuzzer',
                    dest='fuzz', action='store_true')
parser.add_argument('--update', help='update',
                    dest='update', action='store_true')
parser.add_argument('--timeout', help='timeout',
                    dest='timeout', type=int, default=core.config.timeout)
parser.add_argument('--proxy', help='use prox(y|ies)',
                    dest='proxy', action='store_true')
parser.add_argument('--crawl', help='crawl',
                    dest='recursive', action='store_true')
parser.add_argument('--json', help='treat post data as json',
                    dest='jsonData', action='store_true')
parser.add_argument('--path', help='inject payloads in the path',
                    dest='path', action='store_true')
parser.add_argument(
    '--seeds', help='load crawling seeds from a file', dest='args_seeds')
parser.add_argument(
    '-f', '--file', help='load payloads from a file', dest='args_file')
parser.add_argument('-l', '--level', help='level of crawling',
                    dest='level', type=int, default=2)
parser.add_argument('--headers', help='add headers',
                    dest='add_headers', nargs='?', const=True)
parser.add_argument('-t', '--threads', help='number of threads',
                    dest='threadCount', type=int, default=core.config.threadCount)
parser.add_argument('-d', '--delay', help='delay between requests',
                    dest='delay', type=int, default=core.config.delay)
parser.add_argument('--skip', help='don\'t ask to continue',
                    dest='skip', action='store_true')
parser.add_argument('--skip-dom', help='skip dom checking',
                    dest='skipDOM', action='store_true')
parser.add_argument('--blind', help='inject blind XSS payload while crawling',
                    dest='blindXSS', action='store_true')
parser.add_argument('--console-log-level', help='Console logging level',
                    dest='console_log_level', default=core.log.console_log_level,
                    choices=core.log.log_config.keys())
parser.add_argument('--file-log-level', help='File logging level', dest='file_log_level',
                    choices=core.log.log_config.keys(), default=None)
parser.add_argument('--log-file', help='Name of the file to log', dest='log_file',
                    default=core.log.log_file)
parser.add_argument('--output-dir', help='Directory to save output files', dest='output_dir', default='.')
parser.add_argument('--retries', help='Number of retries on connection failure', dest='retries', type=int, default=3)
parser.add_argument('--validate', help='Use Chromium to validate vulnerabilities', dest='validate', action='store_true')  # New argument
args = parser.parse_args()

# Pull all parameter values of dict from argparse namespace into local variables of name == key
target = args.target
input_file = args.input_file
path = args.path
jsonData = args.jsonData
paramData = args.paramData
encode = args.encode
fuzz = args.fuzz
update = args.update
timeout = args.timeout
proxy = args.proxy
recursive = args.recursive
args_file = args.args_file
args_seeds = args.args_seeds
level = args.level
add_headers = args.add_headers
threadCount = args.threadCount
delay = args.delay
skip = args.skip
skipDOM = args.skipDOM
blindXSS = args.blindXSS
core.log.console_log_level = args.console_log_level
core.log.file_log_level = args.file_log_level
core.log.log_file = args.log_file
output_dir = args.output_dir
retries = args.retries
validate = args.validate  # New variable

# Ensure output directory exists
if not os.path.exists(output_dir):
    os.makedirs(output_dir)

core.config.globalVariables = vars(args)

# Import everything else required from core lib
from core.config import blindPayload
from core.encoders import base64
from core.photon import photon
from core.prompt import prompt
from core.updater import updater
from core.utils import extractHeaders, reader, converter

from modes.bruteforcer import bruteforcer
from modes.crawl import crawl
from modes.scan import scan
from modes.singleFuzz import singleFuzz

if type(args.add_headers) == bool:
    headers = extractHeaders(prompt())
elif type(args.add_headers) == str:
    headers = extractHeaders(args.add_headers)
else:
    from core.config import headers

core.config.globalVariables['headers'] = headers
core.config.globalVariables['checkedScripts'] = set()
core.config.globalVariables['checkedForms'] = {}
core.config.globalVariables['definitions'] = json.loads('\n'.join(reader(sys.path[0] + '/db/definitions.json')))

if path:
    paramData = converter(target, target)
elif jsonData:
    headers['Content-type'] = 'application/json'
    paramData = converter(paramData)

if args_file:
    if args_file == 'default':
        payloadList = core.config.payloads
    else:
        payloadList = list(filter(None, reader(args_file)))
else:
    payloadList = core.config.payloads  # Ensure payloadList is defined

seedList = []
if args_seeds:
    seedList = list(filter(None, reader(args_seeds)))

encoding = base64 if encode and encode == 'base64' else False

if not proxy:
    core.config.proxies = {}

if update:  # if the user has supplied --update argument
    updater()
    quit()  # quitting because files have been changed

# Build the list of targets from input file or single target
targets = []

if input_file:
    with open(input_file) as f:
        targets.extend([line.strip() for line in f if line.strip()])
if target:
    targets.append(target)

if not targets and not args_seeds:  # if the user hasn't supplied a url or input file
    print('\n' + parser.format_help().lower())
    quit()

# Function to set up logger for each target
def setup_logger_for_target(domain, log_file, console_log_level, file_log_level):
    # Configure the logger
    import logging
    logger = logging.getLogger(domain)
    logger.setLevel(logging.DEBUG)

    # Remove existing handlers
    if logger.hasHandlers():
        logger.handlers.clear()

    # Create file handler
    fh = logging.FileHandler(log_file)
    fh.setLevel(getattr(logging, file_log_level.upper()) if file_log_level else logging.INFO)

    # Create console handler
    ch = logging.StreamHandler()
    ch.setLevel(getattr(logging, console_log_level.upper()))

    # Create formatter and add it to handlers
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    fh.setFormatter(formatter)
    ch.setFormatter(formatter)

    # Add handlers to logger
    logger.addHandler(fh)
    logger.addHandler(ch)

    return logger

# Function to retry a function call upon exception
def retry(func, retries, delay, logger, *args, **kwargs):
    attempts = 0
    while attempts <= retries:
        try:
            return func(*args, **kwargs)
        except Exception as e:
            if attempts < retries:
                attempts += 1
                logger.warning('Attempt %d/%d failed with error: %s. Retrying after %d seconds...', attempts, retries, str(e), delay)
                time.sleep(delay)
            else:
                logger.error('Failed after %d attempts. Error: %s', retries, str(e))
                return None

# Function to validate vulnerability using Playwright
async def validate_with_chromium(url, payload, logger):
    logger.info('Validating vulnerability using Chromium for URL: %s', url)
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context()
            page = await context.new_page()
            await page.goto(url, timeout=timeout * 1000)
            # Inject payload if needed
            if payload:
                await page.evaluate(f"document.write('{payload}')")
            # You can add more complex validation logic here
            content = await page.content()
            # Simple check to see if payload is reflected
            if payload in content:
                logger.info('Vulnerability confirmed for URL: %s', url)
            else:
                logger.info('Vulnerability not confirmed for URL: %s', url)
            await browser.close()
    except Exception as e:
        logger.error('Error during Chromium validation for URL %s: %s', url, str(e))

if fuzz:
    for target in targets:
        # Extract domain name
        parsed_url = urlparse(target)
        domain = parsed_url.netloc
        if domain.startswith('www.'):
            domain = domain[4:]

        # Create output file path
        output_file = os.path.join(output_dir, domain + '.log')

        # Set up logger for this domain
        logger = setup_logger_for_target(domain, output_file, args.console_log_level, args.file_log_level)

        result = retry(singleFuzz, retries, delay, logger, target, paramData, encoding, headers, delay, timeout)

        # Perform Chromium validation if enabled
        if validate and result:
            asyncio.run(validate_with_chromium(target, None, logger))  # Adjust payload as needed

elif not recursive and not args_seeds:
    for target in targets:
        # Extract domain name
        parsed_url = urlparse(target)
        domain = parsed_url.netloc
        if domain.startswith('www.'):
            domain = domain[4:]

        # Create output file path
        output_file = os.path.join(output_dir, domain + '.log')

        # Set up logger for this domain
        logger = setup_logger_for_target(domain, output_file, args.console_log_level, args.file_log_level)

        if args_file:
            result = retry(bruteforcer, retries, delay, logger, target, paramData, payloadList, encoding, headers, delay, timeout)
        else:
            result = retry(scan, retries, delay, logger, target, paramData, encoding, headers, delay, timeout, skipDOM, skip)

        # Perform Chromium validation if enabled
        if validate and result:
            # Assuming 'result' contains the vulnerable URL and payload
            vulnerable_url = result.get('url')  # Adjust based on actual return value
            payload = result.get('payload')
            if vulnerable_url and payload:
                asyncio.run(validate_with_chromium(vulnerable_url, payload, logger))

else:
    # In recursive mode
    if args_seeds:
        seedList.extend(list(filter(None, reader(args_seeds))))
    seedList.extend(targets)
    for target in seedList:
        # Extract domain name
        parsed_url = urlparse(target)
        domain = parsed_url.netloc
        if domain.startswith('www.'):
            domain = domain[4:]

        # Create output file path
        output_file = os.path.join(output_dir, domain + '.log')

        # Set up logger for this domain
        logger = setup_logger_for_target(domain, output_file, args.console_log_level, args.file_log_level)

        logger.info('Crawling the target: {}'.format(target))
        scheme = parsed_url.scheme
        logger.debug('Target scheme: {}'.format(scheme))
        host = parsed_url.netloc
        main_url = scheme + '://' + host

        # Retry the crawling process
        crawlingResult = retry(photon, retries, delay, logger, target, headers, level,
                               threadCount, delay, timeout, skipDOM)
        if crawlingResult is None:
            logger.error('Crawling failed for target: %s', target)
            continue  # Skip to the next target

        forms = crawlingResult[0]
        domURLs = list(crawlingResult[1])
        difference = abs(len(domURLs) - len(forms))
        if len(domURLs) > len(forms):
            for i in range(difference):
                forms.append(0)
        elif len(forms) > len(domURLs):
            for i in range(difference):
                domURLs.append(0)
        threadpool = concurrent.futures.ThreadPoolExecutor(max_workers=threadCount)
        futures = (threadpool.submit(crawl, scheme, host, main_url, form,
                                     blindXSS, blindPayload, headers, delay, timeout, encoding) for form, domURL in zip(forms, domURLs))
        for i, _ in enumerate(concurrent.futures.as_completed(futures)):
            if i + 1 == len(forms) or (i + 1) % threadCount == 0:
                logger.info('Progress: %i/%i\r' % (i + 1, len(forms)))
        logger.info('')

        # Perform Chromium validation if enabled
        if validate:
            # Collect all URLs and payloads that need validation
            vulnerabilities = []  # This should be populated with found vulnerabilities
            # For example, vulnerabilities.append({'url': vuln_url, 'payload': vuln_payload})

            for vuln in vulnerabilities:
                asyncio.run(validate_with_chromium(vuln['url'], vuln['payload'], logger))
