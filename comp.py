
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


import os



def equal(s1,s2):
    lst1 = list(eval(s1))
    lst2 = list(eval(s2))

    for vuln in lst1:
        vuln['vulnerability'] = vuln['vulnerability'].split("_")[0]
    
    for vuln in lst2:
        vuln['vulnerability'] = vuln['vulnerability'].split("_")[0]
    

    for vuln in lst1:
        vuln['sanitized flows'].sort()
        for lss in vuln['sanitized flows']:
            lss.sort()
    for vuln in lst2:
        vuln['sanitized flows'].sort()
        for lss in vuln['sanitized flows']:
            lss.sort()
    
    equal = True

    print(lst1)
    print(lst2)

    for elm in lst1:
        if elm not in lst2:
            equal = False
            break
    
    if equal:
        for elm in lst2:
            if elm not in lst1:
                equal = False
                break
    return equal


ins = ["1a-basic-flow", "1b-basic-flow", "2-expr-binary-ops", "3a-expr-func-calls", "3b-expr-func-calls", "4a-conds-branching", "4b-conds-branching", "5a-loops-unfolding", "5b-loops-unfolding", "5c-loops-unfolding", "6a-sanitization", "6b-sanitization", "7-conds-implicit", "8-loops-implici", "9-regions-guards"]


if __name__ == '__main__':
    
    for in_case in ins:
        os.system("python3 proj.py slices-20Jan/" + in_case + ".py.json slices-20Jan/" + in_case.split("-")[0] + "-patterns.json > out")

        f = open("slices-20Jan/" + in_case.split("-")[0] + "-output.json", "r")
        expected_str = f.read().replace('\n','')

        f2 = open("out")
        our_str = f2.read().replace('\n','')

        flag = equal(our_str,expected_str)
        print(in_case)
        if(flag):
            print("\t" + bcolors.OKCYAN + "OK" + bcolors.ENDC)
        else:
            print("\t" + bcolors.FAIL + "ERROR" + bcolors.ENDC)
