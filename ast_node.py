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

class Expr:
    def __init__(self, value):
        self.value = construct(value)

    def eval(self):
        print("Expr")
        print(self.value)

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

#DO COMPARE!!!

class BinOp:
    def __init__(self, left, right):
        self.left = construct(left)
        self.right = construct(right)

    def eval(self):
        print("BinOp")
        print(self.left)
        print(self.right)

class Attribute:
    def __init__(self, value, attr):
        self.value = construct(value)
        self.attr = attr              #Not node

    def eval(self):
        print("Attribute")
        print(self.value)
        print(self.attr)


class Constant:
    def __init__(self, value):
        self.value = value               #Not node

    def eval(self):
        print("Constant")
        print(self.value)                #Not node

class Name:
    def __init__(self, id):
        self.id = id               #Not node

    def eval(self):
        print("Name")
        print(self.id)                #Not node

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

