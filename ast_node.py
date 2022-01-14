import sys

class Module:
    def __init__(self, body):
        lst = []
        for elem in body:
            lst.append(construct(elem))
        self.body = lst

    def eval(self):
        print("Module")
        print(self.body)
    
    def show(self, tab = 0):
        print(tab*'\t',"Module:")
        for elm in self.body:
            elm.show(tab+1)

class Expr:
    def __init__(self, value):
        self.value = construct(value)

    def eval(self):
        print("Expr")
        print(self.value)
    
    def show(self,tab):
        print(tab*'\t',"Expression:")
        self.value.show(tab+1)

class Call:
    def __init__(self, args, func):
        lst = []
        for elem in args:
            lst.append(construct(elem))
        self.args = lst
        self.func = construct(func)

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

class Assign:
    def __init__(self, targets, value):
        lst = []
        for elem in targets:
            lst.append(construct(elem))
        self.targets = lst
        self.value = construct(value)

    def eval(self):
        print("Assign")
        print(self.targets)
        print(self.value)
    
    def show(self,tab):
        print(tab*'\t',"Assing:")
        for elm in self.targets:
            elm.show(tab+1)
        self.value.show(tab+1)

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

class Compare:
    def __init__(self, left, comparators):
        self.left = construct(left)
        lst = []
        for elem in comparators:
            lst.append(construct(elem))
        self.comparators = lst
    def eval(self):
        pass

    def show(self,tab):
        print(tab*'\t',"Compare:")
        self.left.show(tab+1)
        for elm in self.comparators:
            elm.show(tab+1)


class BinOp:
    def __init__(self, left, right):
        self.left = construct(left)
        self.right = construct(right)

    def eval(self):
        print("BinOp")
        print(self.left)
        print(self.right)
    
    def show(self,tab):
        print(tab*'\t',"BinOp:")
        self.left.show(tab+1)
        self.right.show(tab+1)

class Attribute:
    def __init__(self, value, attr):
        self.value = construct(value)
        self.attr = attr              #Not node

    def eval(self):
        print("Attribute")
        print(self.value)
        print(self.attr)
    
    def show(self,tab):
        print(tab*'\t',"Attribute:")
        self.value.show(tab+1)
        print((tab+1)*'\t',"attr:",self.attr)


class Constant:
    def __init__(self, value):
        self.value = value               #Not node

    def eval(self):
        print("Constant")
        print(self.value)                #Not node
    
    def show(self,tab):
        print(tab*'\t',"Constant:",self.value)


class Name:
    def __init__(self, id):
        self.id = id               #Not node

    def eval(self):
        print("Name")
        print(self.id)                #Not node
    
    def show(self,tab):
        print(tab*'\t',"Name:",self.id)

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
