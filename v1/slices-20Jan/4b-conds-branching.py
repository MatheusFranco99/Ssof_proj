a=b()
if (g == 0) :
    a = ""
    d = t()
else :
    a=c(a,d)
e(a,d);



b() -> {A,b}
a -> {A,b}, {C,a}

0 -> []
g -> NON_INIT(g)

compare -> NON_INIT(g)

"" -> None
a -> {A,b}, {C,a}, NON_INIT(g, IMPLICIT_ONLY)



# tip: different control paths, via branching, might encode or not different vulnerablities.
# [  {"vulnerability": "A",   "sources": ["b"],  
# "sanitizers": ["t"],   "sinks": ["e"],   "implicit": "no"}, 

# {"vulnerability": "B",   "sources": ["t"],     
# "sanitizers": [],     "sinks": ["a"],     "implicit": "no"},

# {"vulnerability": "C",   "sources": ["a"],     
# "sanitizers": ["c"],     "sinks": ["e"],     "implicit": "no"}]

# [{"vulnerability": "B_1", "source": "d", "sink": "a", 
# "unsanitized flows": "yes", "sanitized flows": []}, 
# {"vulnerability": "A_1", "source": "b", "sink": "e", 
# "unsanitized flows": "yes", "sanitized flows": []}, 
# {"vulnerability": "A_2", "source": "d", "sink": "e", 
# "unsanitized flows": "yes", "sanitized flows": []}, 
# {"vulnerability": "C_1", "source": "a", "sink": "e", 
# "unsanitized flows": "yes", "sanitized flows": [["c"]]}, 
# {"vulnerability": "C_2", "source": "d", "sink": "e", 
# "unsanitized flows": "yes", "sanitized flows": [["c"]]}]


# b() -> {A,b}
# a -> {A,b}, {C,a}

# compare -> NON_Init(g)

# a -> {A,b}, {C,a}, NON_Init(g)

# t() -> {B,t}
# d -> {B,t}, NON_INIT(g, t)

# d -> NON_init(g,d)
# a -> {A,b}, {C,a}, NON_Init(g)
# c -> {A,b}, {C,a,c}, NON_init(g,d [c])
# a -> {A,b}, {C,a,c}, NON_init(g,d [c])


