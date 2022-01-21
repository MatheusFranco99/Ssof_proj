import sys, ast, json
from ast_node import *

# class Vulnerability:
#     def __init__(self, name, sources, sanitizers, sinks, implicit):
#         self.name = name
#         self.sources = sources
#         self.sanitizers = sanitizers
#         self.sinks = sinks
#         self.implicit = implicit
    
#     def __str__(self):
#         text = "name: " + self.name + "\nsources: "
#         for sources in self.sources:
#             text += sources + " "
#         text += "\nsanitizers: "
#         for sanitizers in self.sanitizers:
#             text += sanitizers + " "
#         text += "\nsinks: "
#         for sinks in self.sinks:
#             text += sinks + " "
#         text += "\nimplicit: " + self.implicit
#         return text


def usage():
    sys.stderr.write('Usage: python3 proj.py program.json patterns.json\n')
    sys.exit(1)

# def create_vuln_dict(dictionary):
#     global vuln
#     for key in dictionary:
#         name = key["vulnerability"]
#         sources = key["sources"]
#         sanitizers = key["sanitizers"]
#         sinks = key["sinks"]
#         implicit = key["implicit"]
#         vuln[name] = Vulnerability(name, sources, sanitizers, sinks, implicit)
    

if __name__ == '__main__':
    if len(sys.argv) != 3:
        usage()
    
    # vuln = {}

    #get vulnerabilities
    filename = sys.argv[2]
    text = open(filename).read()
    dictionary = json.loads(text)
    # create_vuln_dict(dictionary)
    # for key in dictionary:
    #     name = key["vulnerability"]
    #     sources = key["sources"]
    #     sanitizers = key["sanitizers"]
    #     sinks = key["sinks"]
    #     implicit = key["implicit"]
    #     vuln[name] = Vulnerability(name, sources, sanitizers, sinks, implicit)
    

    #TODELETE
    # for obj in vuln:
    #     print(vuln[obj])
    #     print("----------------------")

    #get program
    filename = sys.argv[1]
    text = open(filename).read()
    json_dicti = json.loads(text)


    ast = construct(json_dicti)

    ast.show()
    print(names)

    

    ast.analyse(dictionary)
    
    print("##############################################################################################")
    print("table:\n")
    for elm in table:
        print("\t",elm)
    print("##############################################################################################")
    print(vuln)
    print("##############################################################################################")
    for outt in output:
        print(outt)

    """tree = ast.parse(text)
    for node in ast.walk(tree):
        print(node.ast_type)
    for node in ast.walk(tree):
        print(node)"""
    
    