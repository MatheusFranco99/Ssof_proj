a=b('nis')
c=d('oi')
i=""
while (a != "") :
    f = s(c,0,1)

    if (f=="a") :
        i = i + "'"
    else :
        i = i + " "
    a = s(a,1)
z(0,i)

# tip: implicit flows can come from any of the nested conditions/loops


# [  {"vulnerability": "A",   "sources": ["d"],  
# "sanitizers": ["s"],   "sinks": ["z"],   "implicit": "yes"},    
# {"vulnerability": "B",   "sources": ["b"],  
# "sanitizers": ["s"],     "sinks": ["a","z"],   "implicit": "yes"}]



b -> {B,b}
a -> {B,b} -> ++
d -> {A,d}
c -> {A,d}
i -> None

a -> {B,b}

c -> {A,d}
s(c) -> {A,d, [s]}
f -> {A,d, [s]}

f -> {A,d, [s]}

i -> None
i -> None
i -> {A,d, [s]}

a -> {B,b}
s(a) -> {B,b, [s]}
a -> {B,b, [s]}

a -> {B,b, [s]}

c -> {A,d}
s(c) -> {A,d, [s]}
f -> {A,d, [s]}

f -> {A,d, [s]}
i -> {A,d, [s]}


a -> {B,b, [s]}
s(a) -> {B,b, [s]}
a -> {B,b, [s]} ++ 


c,f,i,a, += {B,b}

c -> {A,d}, {B,d}
f -> {A,d, [s]}, {B,d}
i -> {A,d, [s]}, {B,d}
a -> {B,b}, {B,b, [s]}

i -> {A,d, [s]}, {B,b} ++
z -> 