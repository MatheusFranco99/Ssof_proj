a=b('nis')
c=""
while (i == a) :
   c=c + "xpto1"
   i = t(i)
w(s("oi",c))

# tip: while loops can encode implicit flows

# [  {"vulnerability": "A",   "sources": ["b"],  
# "sanitizers": ["s"],   "sinks": ["w","t"],   "implicit": "yes"}]

# b -> {A,b}
# a -> {A,b}
# c -> None

# i == a ( NON_INIT(i), {A,b} )

# c -> None
# i -> NON_INIT(i)
# t(i) -> NON_INIT(i) ++ {A,i, t}
# i -> NON_init(i)

# c -> None
# i -> NON_INIT(i)


# c -> {A,b},{NON_init(i)}
# i -> {A,b},{NON_init(i)}

# c -> {A,b},{NON_init(i)}
# s(c) -> {A,b, [s]},{NON_init(i), [s]}

