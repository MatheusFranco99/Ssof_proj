import sys

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
table = {} # name (for uninstantiated) or pointer: [{vuln: , sources: , sinks: , sanitizers: ,}]
vuln = {}
output = []
table_stack = []

IMPLICIT_PROPAGATION = 'IMPLICIT_PROPAGATION'
INSIDE_IF_WHILE = False

def print_console(*argv):
    # uniq = ""
    # for arg in argv:
    #     uniq += str(arg) + " "
    # uniq = uniq[:-1]
    # print(uniq)
    pass

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
    lst_vulns = []
    for vuln_pattern in vuln:
        lst_vulns += [{'name':vuln[vuln_pattern].name,'source': source,'sanitizers': sanitizers.copy(), 'implicit':vuln[vuln_pattern].implicit}]

    return lst_vulns
    # return {'name': 'especial_vuln_case', 'source': source, 'sanitizers': sanitizers.copy(), 'implicit': 'yes'}
     
def create_vuln_case(name,source,sanitizers,implicit):
    return {'name': name, 'source': source, 'sanitizers': sanitizers.copy(), 'implicit': implicit}


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
    
    def show(self, tab = 0):
        print_console(tab*'\t',"Module:")
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


class Expr:
    def __init__(self, value):
        self.value = construct(value)
    
    def show(self,tab):
        print_console(tab*'\t',"Expression:")
        self.value.show(tab+1)

    def analyse(self):
        
        print_console(bcolors.OKBLUE+"Expr node:"+bcolors.ENDC)
        global names,table,output
        self.value.analyse()
        
        table[self] = table[self.value].copy()
    

class Call:
    def __init__(self, args, func):
        lst = []
        for elem in args:
            lst.append(construct(elem))
        self.args = lst
        self.func = construct(func)

    def show(self, tab):
        print_console(tab*'\t',"Call:")
        print_console((tab+1)*'\t',"Func:",)
        self.func.show(tab+2)
        print_console((tab+1)*'\t',"Args:",)
        for elm in self.args:
            elm.show(tab+2)
    
    def analyse(self):

        global vuln
        
        print_console(bcolors.OKBLUE + "Call node:" + bcolors.ENDC)
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
                        if self.func.id not in table[self][i]['sanitizers']:
                            table[self][i]['sanitizers'] = table[self][i]['sanitizers'].copy() + [self.func.id]
        

        
        print_console("table:")
        for elm in table:
            print_console("\t",elm,table[elm])
        print_console("outputs:")
        for outt in output:
            print_console("\t",outt)
        print_console(bcolors.OKBLUE + "---------------------------------------" + bcolors.ENDC)
        
class Assign:
    def __init__(self, targets, value):
        lst = []
        for elem in targets:
            lst.append(construct(elem))
        self.targets = lst
        self.value = construct(value)
    
    def show(self,tab):
        print_console(tab*'\t',"Assing:")
        for elm in self.targets:
            elm.show(tab+1)
        self.value.show(tab+1)

    
    def analyse(self):
        print_console(bcolors.OKBLUE + "Assign node:" + bcolors.ENDC)
        self.value.analyse()

        leftnames = []
        for elm in self.targets:
            leftnames = leftnames + [elm.id]

        print_console("leftnames:",leftnames)

        for name in leftnames:
            table[name] = table[self.value].copy()
        
        if INSIDE_IF_WHILE:
            for name in leftnames:
                for vuln_case in table[IMPLICIT_PROPAGATION]:
                    table[name] = table[name].copy() + [vuln_case.copy()]


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
                    for i in range(len(table[name])):
                        if is_instance_vuln(table[name][i],vuln[vuln_pattern]):
                            if name not in table[name][i]['sanitizers']:
                                table[name][i]['sanitizers'] = table[name][i]['sanitizers'].copy() + [name]
        


    
        print_console("table:")
        for elm in table:
            print_console("\t",elm,table[elm])
        print_console("Output:")
        for outt in output:
            print_console("\t",outt)
        print_console(bcolors.OKBLUE + "----------------------------------------------------:" + bcolors.ENDC)

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


    def show(self,tab):
        print_console(tab*'\t',"If:")
        self.test.show(tab+1)
        for elm in self.body:
            elm.show(tab+1)
        for elm in self.orelse:
            elm.show(tab+1)
    
    def analyse(self):
        print_console(bcolors.OKBLUE + "If node:" + bcolors.ENDC)
        global table

        # empurra tabela atual pra pilha
        table_stack.append(table.copy())
        
        # corre teste
        self.test.analyse()

        # cria lista com vulnerabilidades implicitas do teste
        if IMPLICIT_PROPAGATION not in table:
            table[IMPLICIT_PROPAGATION] = []
        
        for elm in table[self.test]:
            if(elm['implicit'] == 'yes' and elm not in table[IMPLICIT_PROPAGATION]):
                table[IMPLICIT_PROPAGATION] += [elm]
    
        # empurra tabela atual (if + test) pra pilha
        table_stack.append(table.copy())

        global INSIDE_IF_WHILE
        if_while_flag_previous_value = INSIDE_IF_WHILE
        INSIDE_IF_WHILE = True

        # run body
        for elm in self.body:
            elm.analyse()
        
        # else

        # atualiza as tabelas e a pilha
        table_stack.append(table.copy()) # table do body na pilha

        table = table_stack[-2].copy() # tabela (if + test) para comecar o else

        # run orelse
        for elm in self.orelse:
            elm.analyse()
        
        table3 = table.copy() # orelse table
        table2 = table_stack.pop() # if-body table
        table_stack.pop() # pre if + test table
        table = table_stack.pop() # pre if

        # add, na tabela atual, vulnerabilidades adicionadas a cada variavel dentro do if
        for table_case in [table2,table3]:
            for elm in table_case:
                # check if is a variable
                if isinstance(elm,str) and elm != IMPLICIT_PROPAGATION:
                    
                    if elm not in table:
                        # check if not in both
                        if not (elm in table2 and elm in table3):
                            table[elm] = create_special_vuln_case(elm,[])
                        else: # in both -> always initialized
                            table[elm] = []
                    # add vuln found in body and in orelse
                    for vuln_case in table_case[elm]:
                        if vuln_case not in table[elm]:
                            table[elm] += [vuln_case.copy()]


        INSIDE_IF_WHILE = if_while_flag_previous_value

        print_console("table:")
        for elm in table:
            print_console("\t",elm,table[elm])
        print_console("Output:")
        for outt in output:
            print_console("\t",outt)
        
        print_console(bcolors.OKBLUE + "----------------------------------------------------:" + bcolors.ENDC)

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

    def show(self,tab):
        print_console(tab*'\t',"While:")
        self.test.show(tab+1)
        for elm in self.body:
            elm.show(tab+1)
        for elm in self.orelse:
            elm.show(tab+1)
    
    def analyse(self):
        
        print_console(bcolors.OKBLUE + "While Node:" + bcolors.ENDC)
        global table

        # empurra tabela atual pra pilha
        table_stack.append(table.copy())
        
        # corre teste
        self.test.analyse()

        # cria lista com vulnerabilidades implicitas do teste
        if IMPLICIT_PROPAGATION not in table:
            table[IMPLICIT_PROPAGATION] = []
        for elm in table[self.test]:
            if(elm['implicit'] == 'yes' and elm not in table[IMPLICIT_PROPAGATION]):
                table[IMPLICIT_PROPAGATION] += [elm]

        global INSIDE_IF_WHILE
        if_while_flag_previous_value = INSIDE_IF_WHILE
        INSIDE_IF_WHILE = True



        table_before = table.copy()
        # run body
        for elm in self.body:
            elm.analyse()
        # run body enquanto tabela de variaveis mudar
        while (table_before != table):
            print_console("----------------------------")
            print_console("table_before:")
            for elm in table_before:
                print_console("\t",elm,table_before[elm])
            print_console("table:")
            for elm in table:
                print_console("\t",elm,table[elm])
            print_console("----------------------------")

            difs = []
            for elm in table:
                if elm not in table_before or table[elm] != table_before[elm]:
                    difs += [elm]
            for elm in table_before:
                if elm not in table or table_before[elm] != table[elm]:
                    difs += [elm]
        
            if(difs == []):
                break

            table_before = table.copy()

            # recalcula vuln implicitas no test (caso em que variaveis do compare sao mudadas no body)
            
            # corre teste
            self.test.analyse()

            for elm in table[self.test]:
                if(elm['implicit'] == 'yes' and elm not in table[IMPLICIT_PROPAGATION]):
                    table[IMPLICIT_PROPAGATION] += [elm]
    

            for elm in self.body:
                elm.analyse()
        

        table2 = table.copy()
        table = table_stack.pop()

        # add, na tabela atual, vulnerabilidades adicionadas a cada variavel dentro do while
        for elm in table2:
            # verifica se e uma variavel
            if isinstance(elm,str) and elm != IMPLICIT_PROPAGATION:
                if elm not in table:
                    table[elm] = create_special_vuln_case(elm,[])
                for vuln_case in table2[elm]:
                    if vuln_case not in table[elm]:
                        table[elm] += [vuln_case.copy()]
   

        INSIDE_IF_WHILE = if_while_flag_previous_value

        for elm in self.orelse:
            elm.analyse()

        print_console("table:")
        for elm in table:
            print_console("\t",elm,table[elm])
        print_console("Output:")
        for outt in output:
            print_console("\t",outt)
        
        print_console(bcolors.OKBLUE + "----------------------------------------------------:" + bcolors.ENDC)


class Compare:
    def __init__(self, left, comparators):
        self.left = construct(left)
        lst = []
        for elem in comparators:
            lst.append(construct(elem))
        self.comparators = lst

    def show(self,tab):
        print_console(tab*'\t',"Compare:")
        self.left.show(tab+1)
        for elm in self.comparators:
            elm.show(tab+1)

    
            

    def analyse(self):

        print_console(bcolors.OKBLUE + "Compare Node:" + bcolors.ENDC)
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

        print_console("table:")
        for elm in table:
            print_console("\t",elm,table[elm])
            
        print_console(bcolors.OKBLUE + "----------------------------------------------------" + bcolors.ENDC)
        
        


class BinOp:
    def __init__(self, left, right):
        self.left = construct(left)
        self.right = construct(right)
    

    def show(self,tab):
        print_console(tab*'\t',"BinOp:")
        self.left.show(tab+1)
        self.right.show(tab+1)
    
    def analyse(self):
        self.right.analyse()
        self.left.analyse()
        table[self] = table[self.right].copy()
        for vuln_case in table[self.left]:
            if vuln_case not in table[self]:
                table[self] += [vuln_case]

class Attribute:
    def __init__(self, value, attr):
        self.value = construct(value)
        self.id = attr              #Not node   #self.attr = self.id

    def show(self,tab):
        print_console(tab*'\t',"Attribute:")
        self.value.show(tab+1)
        print_console((tab+1)*'\t',"attr:",self.id)
    
    def analyse(self):
        return
        # self.value.analyse()


class Constant:
    def __init__(self, value):
        self.value = value               #Not node

    def show(self,tab):
        print_console(tab*'\t',"Constant:",self.value)
    
    def analyse(self):
        table[self] = []
        print_console(bcolors.OKCYAN + "Constant: " + str(self.value) + bcolors.ENDC)
        


class Name:
    def __init__(self, id):
        self.id = id               #Not node
        
        global names    
        if id not in names:
            names += [id]

    def show(self,tab):
        print_console(tab*'\t',"Name:",self.id)
    
    def analyse(self):
        print_console(bcolors.OKCYAN + "Name: " + str(self.id) + bcolors.ENDC)
        
        if self.id not in table:
             table[self.id] = create_special_vuln_case(self.id,[])
        table[self] = table[self.id].copy()
        return

class Break:
    def __init__(self):
        pass

    def show(self,tab):
        print_console(tab*'\t',"Break")
    
    def analyse(self):
        return




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
    elif node["ast_type"] == "Break":
        return Break()
    else:
        print_console(node["ast_type"])
        sys.stderr.write("Invalid node\n")
        sys.exit(1)
