from core.config import xsschecker, badTags, fillings, eFillings, lFillings, jFillings, eventHandlers, tags, functions
from core.jsContexter import jsContexter
from core.utils import randomUpper as r, genGen, extractScripts


def generator(occurences, response):
    scripts = extractScripts(response)
    index = 0
    vectors = {11: set(), 10: set(), 9: set(), 8: set(), 7: set(),
               6: set(), 5: set(), 4: set(), 3: set(), 2: set(), 1: set()}

    for i in occurences:
        context = occurences[i]['context']
        if context == 'html':
            lessBracketEfficiency = occurences[i]['score']['<']
            greatBracketEfficiency = occurences[i]['score']['>']
            ends = ['//']
            badTag = occurences[i]['details']['badTag'] if 'badTag' in occurences[i]['details'] else ''
            if greatBracketEfficiency == 100:
                ends.append('>')
            if lessBracketEfficiency:
                payloads = genGen(fillings, eFillings, lFillings, eventHandlers, tags, functions, ends, badTag)
                for payload in payloads:
                    vectors[10].add(payload)

        elif context == 'attribute':
            found = False
            tag = occurences[i]['details']['tag']
            Type = occurences[i]['details']['type']
            quote = occurences[i]['details']['quote'] or ''
            attributeName = occurences[i]['details']['name']
            attributeValue = occurences[i]['details']['value']
            payloads = []

            if Type == 'name':
                payloads = genGen(fillings, eFillings, lFillings, eventHandlers, tags, functions, [quote])
            elif Type == 'value':
                payloads = genGen(fillings, eFillings, lFillings, eventHandlers, tags, functions, [quote + attributeValue + quote])

            for payload in payloads:
                vectors[9].add(f'{tag} {attributeName}={payload}')

        elif context == 'script':
            payloads = jsContexter(occurences[i], scripts, index)
            index += 1
            for payload in payloads:
                vectors[11].add(payload)

    return vectors
