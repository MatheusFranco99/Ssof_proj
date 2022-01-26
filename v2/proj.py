import sys, ast, json
from ast_node import *

def process_output(output):
    processed_output = []
    cont = {}
    for flow in output:
        vuln = flow["name"]
        if flow["name"] in cont.keys():
            cont[flow["name"]] += 1
            vuln += "_" + str(cont[flow["name"]])
        else:
            vuln += "_1"
            cont[flow["name"]] = 1
        source = flow["source"]
        sink = flow["sink"]
        option = flow["unsanitized"]
        sanitized = flow["sanitizers"]
        sanitized = [ele for ele in sanitized if ele != []]
        processed_output += [{"vulnerability": vuln, "source": source, "sink": sink, "unsanitized flows": option, "sanitized flows": sanitized}]
    print(str(processed_output).replace('\'','\"'))


def usage():
    sys.stderr.write('Usage: python3 proj.py program.json patterns.json\n')
    sys.exit(1)


if __name__ == '__main__':
    if len(sys.argv) != 3:
        usage()
    

    #get vulnerabilities
    filename = sys.argv[2]
    text = open(filename).read()
    dictionary = json.loads(text)

    #get program
    filename = sys.argv[1]
    text = open(filename).read()
    json_dicti = json.loads(text)


    ast = construct(json_dicti)
    ast.analyse(dictionary)
    process_output(output)
    
    