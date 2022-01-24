import sys

"""

tainted = {'name_var':{'source':s, 'unsunitized_flow':y/n, 'sanitized'=[]}}




"""

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


names = []


table = {}
# name (for uninstantiated) or pointer: [{vuln: , sources: , sinks: , sanitizers: ,}]


vuln = {}
output = []

table_stack = []

IMPLICIT_PROPAGATION = 'IMPLICIT_PROPAGATION'

def create_output_case(name,source, sink, unsanitized, sanitizers):
    global output
    if sanitizers == []:
        output += [{'name': name, 'source': source, 'sink': sink, 'unsanitized': unsanitized, 'sanitizers': []}]
    else:
        output += [{'name': name, 'source': source, 'sink': sink, 'unsanitized': unsanitized, 'sanitizers': [sanitizers.copy()]}]

def add_output(vuln_case, vuln_pattern,sink):
    name = vuln_pattern.name
    source = vuln_case['source']
    sanitizers = []
    for snt in vuln_case['sanitizers']:
        if snt in vuln_pattern.sanitizers:
            sanitizers.append(snt)
    unsanitized = 'yes'
    if sanitizers != []:
        unsanitized = 'no'

    
    global output
    for outt in output:
        if (outt['name'] == name and outt['source'] == source and outt['sink'] == sink):
            # already exists
            if outt['unsanitized'] != unsanitized:
                outt['unsanitized'] = 'yes'
            
            if sanitizers != [] and sanitizers not in outt['sanitizers']:
                outt['sanitizers'] += [sanitizers]
            
            return
    
    # doesn't exist
    create_output_case(name,source, sink, unsanitized, sanitizers)
    

def is_special_vuln(vuln_case):
    return vuln_case['name'] == 'especial_vuln_case'
       
def create_special_vuln_case(source,sanitizers):
    return {'name': 'especial_vuln_case', 'source': source, 'sanitizers': sanitizers.copy(), 'implicit': 'yes'}
     
def create_vuln_case(name,source,sanitizers,implicit):
    return {'name': name, 'source': source, 'sanitizers': sanitizers.copy(), 'implicit': implicit}

def add_sanitizer(vuln_case,sanitizer: str):
    vuln_case['sanitizers'] += [sanitizer]
    return vuln_case

def is_instance_vuln(vuln_case,vuln_pattern):
    if(is_special_vuln(vuln_case)):
        return True
    return vuln_case['name'] == vuln_pattern.name

class Module:
    def __init__(self, body):
        lst = []
        for elem in body:
            lst.append(construct(elem))
        self.body = lst
        
        self.tainted = False
        self.own_vuln = 0

        

    def eval(self):
        print("Module")
        print(self.body)
    
    def show(self, tab = 0):
        print(tab*'\t',"Module:")
        for elm in self.body:
            elm.show(tab+1)
    
    def analyse(self,dictionary):
        global vuln
        for key in dictionary:
            name = key["vulnerability"]
            sources = key["sources"]
            sanitizers = key["sanitizers"]
            sinks = key["sinks"]
            implicit = key["implicit"]
            vuln[name] = Vulnerability(name, sources, sanitizers, sinks, implicit)
        
        for elm in self.body:
            elm.analyse()
            to_pop = []
            for elm in table:
                if(not isinstance(elm,str)):
                    to_pop += [elm]
            for elm in to_pop:
                del table[elm]

    def getnames(self):
        names = []
        for elm in self.body:
            names += [elm.getnames()]
        return names

class Expr:
    def __init__(self, value):
        self.value = construct(value)
        self.tainted = False
        self.own_vuln = 0

    def eval(self):
        print("Expr")
        print(self.value)
    
    def show(self,tab):
        print(tab*'\t',"Expression:")
        self.value.show(tab+1)


    def analyse(self):
        
        print(bcolors.OKBLUE+"Expr node:"+bcolors.ENDC)
        global names,table,output
        self.value.analyse()
        
        table[self] = table[self.value].copy()
    
    def getnames(self):
        return self.value.getnames()
        

class Call:
    def __init__(self, args, func):
        lst = []
        for elem in args:
            lst.append(construct(elem))
        self.args = lst
        self.func = construct(func)
        self.tainted = False
        self.own_vuln = 0

    def eval(self):
        print("Call")
        print(self.args)
        print(self.func)
    
    def show(self, tab):
        print(tab*'\t',"Call:")
        print((tab+1)*'\t',"Func:",)
        self.func.show(tab+2)
        print((tab+1)*'\t',"Args:",)
        for elm in self.args:
            elm.show(tab+2)
    
    def analyse(self):

        global vuln
        
        print(bcolors.OKBLUE + "Call node:" + bcolors.ENDC)
        for elm in self.args:
            elm.analyse()

        table[self] = []
        for elm in self.args:
            for vul_case in table[elm]:
                if vul_case not in table[self]:
                    table[self] += [vul_case.copy()]
        
        
        # source
        for vuln_pattern in vuln:
            if(self.func.id in vuln[vuln_pattern].sources):
                vul_case = create_vuln_case(vuln[vuln_pattern].name,self.func.id,[],vuln[vuln_pattern].implicit)
                if vul_case not in table[self]:
                    table[self] += [vul_case.copy()]

        # sink
        for vuln_pattern in vuln:
            if(self.func.id in vuln[vuln_pattern].sinks):
                for vuln_case in table[self]:
                    if is_instance_vuln(vuln_case,vuln[vuln_pattern]):
                        add_output(vuln_case,vuln[vuln_pattern],self.func.id)


        # sanitizer
        for vuln_pattern in vuln:
            if(self.func.id in vuln[vuln_pattern].sanitizers):
                for i in range(len(table[self])):
                    if is_instance_vuln(table[self][i],vuln[vuln_pattern]):
                        #add_sanitizer(vuln_case,self.func.id)
                        if self.func.id not in table[self][i]['sanitizers']:
                            table[self][i]['sanitizers'] = table[self][i]['sanitizers'].copy() + [self.func.id]
        

        
        print("table:")
        for elm in table:
            print("\t",elm,table[elm])
        print("outputs:")
        for outt in output:
            print("\t",outt)
        print(bcolors.OKBLUE + "---------------------------------------" + bcolors.ENDC)
        

class Assign:
    def __init__(self, targets, value):
        lst = []
        for elem in targets:
            lst.append(construct(elem))
        self.targets = lst
        self.value = construct(value)
        self.tainted = False
        self.own_vuln = 0

    def eval(self):
        print("Assign")
        print(self.targets)
        print(self.value)
    
    def show(self,tab):
        print(tab*'\t',"Assing:")
        for elm in self.targets:
            elm.show(tab+1)
        self.value.show(tab+1)
    
    def analyse(self):
        print(bcolors.OKBLUE + "Assign node:" + bcolors.ENDC)
        self.value.analyse()

        leftnames = []
        for elm in self.targets:
            leftnames = leftnames + elm.getnames()

        print("leftnames:",leftnames)

        for name in leftnames:
            table[name] = table[self.value]
            # if name not in table:
            #     table[name] = table[self.value]
            # else:
            #     for elm in table[self.value]:
            #         if elm not in table[name]:
            #             table[name] += [elm.copy()]
        
        # if IMPLICIT_PROPAGATION in table:
        #     for name in leftnames:
        #         for implicit_vuln in table[IMPLICIT_PROPAGATION]:
        #             table[name] += [implicit_vuln.copy()]


        for name in leftnames:
            # source
            for vuln_pattern in vuln:
                if(name in vuln[vuln_pattern].sources):
                    vul_case = create_vuln_case(vuln[vuln_pattern].name,name,[],vuln[vuln_pattern].implicit)
                    if vul_case not in table[name]:
                        table[name] += [vul_case.copy()]

            # sink
            for vuln_pattern in vuln:
                if(name in vuln[vuln_pattern].sinks):
                    for vuln_case in table[name]:
                        if is_instance_vuln(vuln_case,vuln[vuln_pattern]) and vuln_case['source'] != name:
                            add_output(vuln_case,vuln[vuln_pattern],name)

            # sanitizer
            for vuln_pattern in vuln:
                if(name in vuln[vuln_pattern].sanitizers):
                    for vuln_case in table[name]:
                        if is_instance_vuln(vuln_case,vuln[vuln_pattern]):
                            add_sanitizer(vuln_case,name)

    
        print("table:")
        for elm in table:
            print("\t",elm,table[elm])
        print("Output:")
        for outt in output:
            print("\t",outt)
        print(bcolors.OKBLUE + "----------------------------------------------------:" + bcolors.ENDC)

class If:
    def __init__(self, test, body, orelse):
        self.test = construct(test)
        lst = []
        for elem in body:
            lst.append(construct(elem))
        self.body = lst
        lst = []
        for elem in orelse:
            lst.append(construct(elem))
        self.orelse = lst
        self.tainted = False
        self.own_vuln = 0
    
    def eval(self):
        print("If")
        print(self.test)
        print(self.body)
        print(self.orelse)

    def show(self,tab):
        print(tab*'\t',"If:")
        self.test.show(tab+1)
        for elm in self.body:
            elm.show(tab+1)
        for elm in self.orelse:
            elm.show(tab+1)
    
    def analyse(self):
        print(bcolors.OKBLUE + "If node:" + bcolors.ENDC)
        global table

        self.test.analyse()

        if IMPLICIT_PROPAGATION not in table:
            table[IMPLICIT_PROPAGATION] = []
        for elm in table[self.test]:
            if(elm['implicit'] == 'yes' and elm not in table[IMPLICIT_PROPAGATION]):
                table[IMPLICIT_PROPAGATION] += [elm]
    
        table_stack.append(table.copy())

        for elm in self.body:
            elm.analyse()
        
        previous_table = table_stack.pop()
        table_stack.append(previous_table)
        table_stack.append(table.copy())

        table = previous_table.copy()

        for elm in self.orelse:
            elm.analyse()
        
        table3 = table.copy()
        table2 = table_stack.pop()
        table = table_stack.pop()
        for table_case in [table2,table3]:
            for elm in table_case:
                if isinstance(elm,str) and elm != IMPLICIT_PROPAGATION:
                    if elm not in table:
                        table[elm] = [create_special_vuln_case(elm,[])]
                    for vuln_case in table_case[elm]:
                        if vuln_case not in table[elm]:
                            table[elm] += [vuln_case.copy()]
        
        print("table:")
        for elm in table:
            print("\t",elm,table[elm])
        print("Output:")
        for outt in output:
            print("\t",outt)
        
        print(bcolors.OKBLUE + "----------------------------------------------------:" + bcolors.ENDC)



class While:
    def __init__(self, test, body, orelse):
        self.test = construct(test)
        lst = []
        for elem in body:
            lst.append(construct(elem))
        self.body = lst
        lst = []
        for elem in orelse:
            lst.append(construct(elem))
        self.orelse = lst
        self.tainted = False
        self.own_vuln = 0
    
    def eval(self):
        print("While")
        print(self.test)
        print(self.body)
        print(self.orelse)
    
    def show(self,tab):
        print(tab*'\t',"While:")
        self.test.show(tab+1)
        for elm in self.body:
            elm.show(tab+1)
        for elm in self.orelse:
            elm.show(tab+1)
    
    def analyse(self):
        
        print(bcolors.OKBLUE + "While Node:" + bcolors.ENDC)
        global table

        self.test.analyse()

        if IMPLICIT_PROPAGATION not in table:
            table[IMPLICIT_PROPAGATION] = []
        for elm in table[self.test]:
            if(elm['implicit'] == 'yes' and elm not in table[IMPLICIT_PROPAGATION]):
                table[IMPLICIT_PROPAGATION] += [elm]
    
        table_stack.append(table.copy())

        for elm in self.body:
            elm.analyse()
        for elm in self.body:
            elm.analyse()
        
        previous_table = table_stack.pop()
        table_stack.append(previous_table)
        table_stack.append(table.copy())

        table = previous_table.copy()

        for elm in self.orelse:
            elm.analyse()
        for elm in self.orelse:
            elm.analyse()
        
        table3 = table.copy()
        table2 = table_stack.pop()
        table = table_stack.pop()
        for table_case in [table2,table3]:
            for elm in table2:
                if isinstance(elm,str) and elm != IMPLICIT_PROPAGATION:
                    if elm not in table:
                        table[elm] = [create_special_vuln_case(elm,[])]
                    for vuln_case in table2[elm]:
                        if vuln_case not in table[elm]:
                            table[elm] += [vuln_case.copy()]
        
        print("table:")
        for elm in table:
            print("\t",elm,table[elm])
        print("Output:")
        for outt in output:
            print("\t",outt)
        
        print(bcolors.OKBLUE + "----------------------------------------------------:" + bcolors.ENDC)


class Compare:
    def __init__(self, left, comparators):
        self.left = construct(left)
        lst = []
        for elem in comparators:
            lst.append(construct(elem))
        self.comparators = lst
        self.tainted = False
        self.own_vuln = 0

    def eval(self):
        pass

    def show(self,tab):
        print(tab*'\t',"Compare:")
        self.left.show(tab+1)
        for elm in self.comparators:
            elm.show(tab+1)
    
    
    def analyse(self):
        print(bcolors.OKBLUE + "Compare Node:" + bcolors.ENDC)
        for elm in self.comparators:
            elm.analyse()
        self.left.analyse()
    
        table[self] = []
        for elm in table[self.left]:
            if elm not in table[self]:
                table[self] += [elm.copy()]
        
        for comp in self.comparators:
            for elm in table[comp]:
                if elm not in table[self]:
                    table[self] += [elm.copy()]
        print("table:")
        for elm in table:
            print("\t",elm,table[elm])
            
        print(bcolors.OKBLUE + "----------------------------------------------------" + bcolors.ENDC)


        
        


class BinOp:
    def __init__(self, left, right):
        self.left = construct(left)
        self.right = construct(right)
        self.tainted = False
        self.own_vuln = 0

    def eval(self):
        print("BinOp")
        print(self.left)
        print(self.right)
    
    def show(self,tab):
        print(tab*'\t',"BinOp:")
        self.left.show(tab+1)
        self.right.show(tab+1)
    
    def analyse(self):
        self.right.analyse()
        self.left.analyse()
        table[self] = table[self.right].copy()
        for vuln_case in table[self.left]:
            if vuln_case not in table[self]:
                table[self] += [vuln_case]
    
    def getnames(self):
        return self.left.getnames() + self.right.getnames()
        


class Attribute:
    def __init__(self, value, attr):
        self.value = construct(value)
        self.id = attr              #Not node   #self.attr = self.id
        self.tainted = False
        self.own_vuln = 0

    def eval(self):
        print("Attribute")
        print(self.value)
        print(self.id)
    
    def show(self,tab):
        print(tab*'\t',"Attribute:")
        self.value.show(tab+1)
        print((tab+1)*'\t',"attr:",self.id)
    
    def analyse(self):
        return
        self.value.analyse()
        self.tainted = self.value.tainted


class Constant:
    def __init__(self, value):
        self.value = value               #Not node
        self.tainted = False
        self.own_vuln = 0

    def eval(self):
        print("Constant")
        print(self.value)                #Not node
    
    def show(self,tab):
        print(tab*'\t',"Constant:",self.value)
    
    def analyse(self):
        table[self] = []
        print(bcolors.OKCYAN + "Constant: " + str(self.value) + bcolors.ENDC)
        


class Name:
    def __init__(self, id):
        self.id = id               #Not node
        self.tainted = False
        self.own_vuln = 0
        
        global names    
        if id not in names:
            names += [id]

    def eval(self):
        print("Name")
        print(self.id)                #Not node
    
    def show(self,tab):
        print(tab*'\t',"Name:",self.id)
    
    def analyse(self):
        print(bcolors.OKCYAN + "Name: " + str(self.id) + bcolors.ENDC)
        
        if self.id not in table:
             table[self.id] = [create_special_vuln_case(self.id,[])]
        table[self] = table[self.id].copy()
        return

    def getnames(self):
        return [self.id]



def construct(node):
    if node["ast_type"] == "Module":
        return Module(node["body"])
    elif node["ast_type"] == "Expr":
        return Expr(node["value"])
    elif node["ast_type"] == "Call":
        return Call(node["args"], node["func"])
    elif node["ast_type"] == "Assign":
        return Assign(node["targets"], node["value"])
    elif node["ast_type"] == "If":
        return If(node["test"], node["body"], node["orelse"])
    elif node["ast_type"] == "While":
        return While(node["test"], node["body"], node["orelse"])
    elif node["ast_type"] == "Compare":
        return Compare(node["left"], node["comparators"])
    elif node["ast_type"] == "BinOp":
        return BinOp(node["left"], node["right"])
    elif node["ast_type"] == "Attribute":
        return Attribute(node["value"], node["attr"])
    elif node["ast_type"] == "Name":
        return Name(node["id"])
    elif node["ast_type"] == "Constant":
        return Constant(node["value"])
    else:
        sys.stderr.write("Invalid node\n")
        sys.exit(1)
