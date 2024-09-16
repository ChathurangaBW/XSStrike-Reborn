import json
import random
import re
from urllib.parse import urlparse

import core.config
from core.config import xsschecker


def converter(data, url=False):
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
    string = re.sub(r'\s|\w', '', string)
    return len(string)


def closest(number, numbers):
    difference = [abs(list(numbers.values())[0]), {}]
    for index, i in numbers.items():
        diff = abs(number - i)
        if diff < difference[0]:
            difference = [diff, {index: i}]
    return difference[1]


def fillHoles(original, new):
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
    headers = headers.replace('\\n', '\n')
    sorted_headers = {}
    matches = re.findall(r'(.*):\s(.*)', headers)
    for match in matches:
        header = match[0]
        value = match[1].rstrip(',')
        sorted_headers[header] = value
    return sorted_headers


def replaceValue(mapping, old, new, strategy=None):
    another_map = strategy(mapping) if strategy else mapping
    if old in another_map.values():
        for k in another_map.keys():
            if another_map[k] == old:
                another_map[k] = new
    return another_map


def getUrl(url, GET):
    if GET:
        return url.split('?')[0]
    else:
        return url


def extractScripts(response):
    scripts = []
    matches = re.findall(r'(?s)<script.*?>(.*?)</script>', response.lower())
    for match in matches:
        if xsschecker in match:
            scripts.append(match)
    return scripts


def randomUpper(string):
    return ''.join(random.choice((x, y)) for x, y in zip(string.upper(), string.lower()))


def flattenParams(currentParam, params, payload):
    flatted = []
    for name, value in params.items():
        if name == currentParam:
            value = payload
        flatted.append(name + '=' + value)
    return '?' + '&'.join(flatted)


def getParams(url, data, GET):
    params = {}
    if GET and '?' in url:
        data = url.split('?')[1]
        if data[:1] == '?':
            data = data[1:]
    elif data:
        if isinstance(data, dict):
            params = data
        else:
            try:
                params = json.loads(data.replace("'", '"'))
                return params
            except json.decoder.JSONDecodeError:
                pass
    if not params:
        parts = data.split('&')
        for part in parts:
            each = part.split('=')
            if len(each) < 2:
                each.append('')
            try:
                params[each[0]] = each[1]
            except IndexError:
                params = None
    return params


def writer(obj, path):
    kind = str(type(obj)).split('\'')[0]
    if kind == 'list' or kind == 'tuple':
        obj = '\n'.join(obj)
    elif kind == 'dict':
        obj = json.dumps(obj, indent=4)
    with open(path, 'w+', encoding='utf-8') as savefile:
        savefile.write(str(obj))


def reader(path):
    with open(path, 'r', encoding='utf-8') as f:
        result = [line.rstrip('\n') for line in f]
    return result


def js_extractor(response):
    scripts = []
    matches = re.findall(r'<(?:script|SCRIPT).*?(?:src|SRC)=([^\s>]+)', response)
    for match in matches:
        match = match.replace('\'', '').replace('"', '').replace('`', '')
        scripts.append(match)
    return scripts


def handle_anchor(parent_url, url):
    scheme = urlparse(parent_url).scheme
    if url[:4] == 'http':
        return url
    elif url[:2] == '//':
        return scheme + ':' + url
    elif url.startswith('/'):
        host = urlparse(parent_url).netloc
        return scheme + '://' + host + url
    elif parent_url.endswith('/'):
        return parent_url + url
    else:
        return parent_url + '/' + url


def deJSON(data):
    return data.replace('\\\\', '\\')


def getVar(name):
    return core.config.globalVariables[name]


def updateVar(name, data, mode=None):
    if mode:
        if mode == 'append':
            core.config.globalVariables[name].append(data)
        elif mode == 'add':
            core.config.globalVariables[name].add(data)
    else:
        core.config.globalVariables[name] = data


def isBadContext(position, non_executable_contexts):
    bad_context = ''
    for each in non_executable_contexts:
        if each[0] < position < each[1]:
            bad_context = each[2]
            break
    return bad_context


def equalize(array, number):
    while len(array) < number:
        array.append('')


def escaped(position, string):
    usable = string[:position][::-1]
    match = re.search(r'^\\*', usable)
    if match:
        match = match.group()
        return len(match) % 2 != 0
    return False


def genGen(fillings, eFillings, lFillings, eventHandlers, tags, functions, ends, badTag=None):
    vectors = []
    r = randomUpper  # randomUpper randomly converts characters to uppercase

    for tag in tags:
        bait = xsschecker if tag in ['d3v', 'a'] else ''
        for eventHandler in eventHandlers:
            if tag in eventHandlers[eventHandler]:
                for function in functions:
                    for filling in fillings:
                        for eFilling in eFillings:
                            for lFilling in lFillings:
                                for end in ends:
                                    if tag in ['d3v', 'a'] and '>' in ends:
                                        end = '>'
                                    breaker = f'</{r(badTag)}>' if badTag else ''
                                    vector = breaker + f'<{r(tag)}{filling}{r(eventHandler)}={eFilling}{function}{lFilling}{end}{bait}'
                                    vectors.append(vector)
    return vectors
