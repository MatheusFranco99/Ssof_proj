a=b('nis')
c=""
d=""
while (e == "") :
    c = d
    if (x == 33) :
        d = a
    a = s(a+1)
q=z(c)

# tip: different control paths, via number of loops, might encode or not different vulnerablities. 

# [  {"vulnerability": "A",   "sources": ["b"],  
# "sanitizers": ["s"],   "sinks": ["q"],   "implicit": "no"},    
# {"vulnerability": "B",   "sources": ["b"],  
# "sanitizers": [],   "sinks": ["c"],   "implicit": "no"}]

# b -> {A,b}, {B,b}
# a -> {A,b}, {B,b}
# c -> None
# d -> None

# e -> Non_init(e)

# d -> None
# c -> None

# x -> Non_init(x)
# a -> {A,b}, {B,b}
# d -> {A,b}, {B,b}

# a -> {A,b}, {B,b}
# s(a+1) -> {A,b, [s]}, {B,b}
# a -> {A,b, [s]}, {B,b}

# d -> {A,b}, {B,b}
# c -> {A,b}, {B,b}

# x -> Non_init(x)
# a -> {A,b, [s]}, {B,b}
# d -> {A,b, [s]}, {B,b}

# a -> {A,b, [s]}, {B,b}
# s(a) -> {A,b, [s]}, {B,b}
# a -> {A,b, [s]}, {B,b}

# c -> non_init(c)
# z(c) -> non_init(c)
# q
