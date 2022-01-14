import sys, ast, json
from ast_node import *

class Vulnerability:
    def __init__(self, name, sources, sanitizers, sinks, implicit):
        self.name = name
        self.sources = sources
        self.sanitizers = sanitizers
        self.sinks = sinks
        self.implicit = implicit
    
    def __str__(self):
        text = "name: " + self.name + "\nsources: "
        for sources in self.sources:
            text += sources + " "
        text += "\nsanitizers: "
        for sanitizers in self.sanitizers:
            text += sanitizers + " "
        text += "\nsinks: "
        for sinks in self.sinks:
            text += sinks + " "
        text += "\nimplicit: " + self.implicit
        return text


def usage():
    sys.stderr.write('Usage: python3 proj.py program.json patterns.json\n')
    sys.exit(1)

if __name__ == '__main__':
    if len(sys.argv) != 3:
        usage()
    
    vuln = {}

    #get vulnerabilities
    filename = sys.argv[2]
    text = open(filename).read()
    dictionary = json.loads(text)
    for key in dictionary:
        name = key["vulnerability"]
        sources = key["sources"]
        sanitizers = key["sanitizers"]
        sinks = key["sinks"]
        implicit = key["implicit"]
        vuln[name] = Vulnerability(name, sources, sanitizers, sinks, implicit)
    
    #TODELETE
    for obj in vuln:
        print(vuln[obj])
        print("----------------------")

    #get program
    filename = sys.argv[1]
    text = open(filename).read()
    json_dicti = json.loads(text)

    ast = construct(json_dicti)

    """tree = ast.parse(text)
    for node in ast.walk(tree):
        print(node.ast_type)
    for node in ast.walk(tree):
        print(node)"""