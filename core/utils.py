import json
import random
import re
from urllib.parse import urlparse

import core.config
from core.config import xsschecker


def converter(data, url=False):
    """
    Converts a string into a dictionary, or a dictionary into a string, depending on input.
    Can also convert URL paths into a dictionary or vice versa.

    Args:
        data (str or dict): Input data to be converted.
        url (bool): If True, data is treated as a URL string.

    Returns:
        dict or str: Converted data (dict if parsing, str if encoding).
    """
    try:
        if isinstance(data, str):
            if url:
                dictized = {}
                parts = data.split('/')[3:]
                for part in parts:
                    dictized[part] = part
                return dictized
            else:
                return json.loads(data)
        else:
            if url:
                url = urlparse(url).scheme + '://' + urlparse(url).netloc
                for part in list(data.values()):
                    url += '/' + part
                return url
            else:
                return json.dumps(data)
    except (json.JSONDecodeError, ValueError) as e:
        raise ValueError(f"Error converting data: {e}")


def counter(string):
    """
    Counts non-whitespace, non-alphanumeric characters in a string.

    Args:
        string (str): Input string.

    Returns:
        int: Number of special characters in the string.
    """
    string = re.sub(r'\s|\w', '', string)
    return len(string)


def closest(number, numbers):
    """
    Finds the closest value to the target number in a dictionary of numbers.

    Args:
        number (int or float): The target number.
        numbers (dict): A dictionary of numbers to search.

    Returns:
        dict: A dictionary containing the closest value.
    """
    difference = [abs(list(numbers.values())[0]), {}]
    for index, i in numbers.items():
        diff = abs(number - i)
        if diff < difference[0]:
            difference = [diff, {index: i}]
    return difference[1]


def fillHoles(original, new):
    """
    Fills gaps between two lists by aligning values, filling gaps with zeros.

    Args:
        original (list): The original list.
        new (list): The list with holes to be filled.

    Returns:
        list: The filled list.
    """
    filler = 0
    filled = []
    for x, y in zip(original, new):
        if int(x) == (y + filler):
            filled.append(y)
        else:
            filled.extend([0, y])
            filler += (int(x) - y)
    return filled


def stripper(string, substring, direction='right'):
    """
    Strips a substring from the left or right of a string.

    Args:
        string (str): Input string.
        substring (str): Substring to strip.
        direction (str): Direction to strip ('right' or 'left').

    Returns:
        str: The stripped string.
    """
    done = False
    stripped_string = ''
    if direction == 'right':
        string = string[::-1]
    for char in string:
        if char == substring and not done:
            done = True
        else:
            stripped_string += char
    if direction == 'right':
        stripped_string = stripped_string[::-1]
    return stripped_string


def extractHeaders(headers):
    """
    Extracts HTTP headers from a string format and converts them into a dictionary.

    Args:
        headers (str): String containing HTTP headers.

    Returns:
        dict: Dictionary containing header key-value pairs.
    """
    headers = headers.replace('\\n', '\n')
    sorted_headers = {}
    matches = re.findall(r'(.*):\s(.*)', headers)
    for match in matches:
        header = match[0]
        value = match[1].rstrip(',')
        sorted_headers[header] = value
    return sorted_headers


def replaceValue(mapping, old, new, strategy=None):
    """
    Replaces an old value with a new one in a dictionary, with optional copy strategy.

    Args:
        mapping (dict): The dictionary to modify.
        old: The value to replace.
        new: The new value.
        strategy: Optional copy strategy (e.g., shallow copy, deep copy).

    Returns:
        dict: Modified dictionary with the value replaced.
    """
    another_map = strategy(mapping) if strategy else mapping
    if old in another_map.values():
        for k in another_map.keys():
            if another_map[k] == old:
                another_map[k] = new
    return another_map


def getUrl(url, GET):
    """
    Extracts the base URL without query parameters for GET requests.

    Args:
        url (str): The full URL.
        GET (bool): Whether it's a GET request.

    Returns:
        str: The base URL without query parameters.
    """
    if GET:
        return url.split('?')[0]
    else:
        return url


def extractScripts(response):
    """
    Extracts script contents from a response body for XSS checking.

    Args:
        response (str): The response content (HTML).

    Returns:
        list: List of script contents that include XSS payloads.
    """
    scripts = []
    matches = re.findall(r'(?s)<script.*?>(.*?)</script>', response.lower())
    for match in matches:
        if xsschecker in match:
            scripts.append(match)
    return scripts
