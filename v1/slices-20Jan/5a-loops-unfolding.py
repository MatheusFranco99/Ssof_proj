a=b('nis')
while (e == "") :
    c = d(a)
    e = f(c)
    a = e
g = h(a)

# tip: sources, sanitizers and sinks can appear inside loops

# [  {"vulnerability": "A",   "sources": ["b"],  
# "sanitizers": ["d"],   "sinks": ["h"],   "implicit": "no"},    
# {"vulnerability": "B",   "sources": ["f"],  
# "sanitizers": ["t"],   "sinks": ["c"],   "implicit": "no"}]


# a -> {A,b}

# e -> NON_INIT(e, implicit_only)

# a -> {A,b}
# d(A) -> {A,b,[d]}
# c -> {A,b,[d]}
# c -> {A,b,[d]}
# f(c) -> {A,b,[d]}, {B,f}
# e -> {A,b,[d]}, {B,f}
# a -> {A,b,[d]}, {B,f}

# a -> {A,b,[d]}, {B,f}
# d(a) -> {A,b,[d]}, {B,f}
# c -> {A,b,[d]}, {B,f} ++ out {B,f,c}

# c -> {A,b,[d]}, {B,f}
# f(c) -> {A,b,[d]}, {B,f}
# e -> {A,b,[d]}, {B,f}

# e -> {A,b,[d]}, {B,f}
# a -> {A,b,[d]}, {B,f}

# a -> {A,b}, {A,b,[d]}, {B,f}
# h(a) -> {A,b}, {A,b,[d]}, {B,f} ++ out {A,b,[],[d]}
