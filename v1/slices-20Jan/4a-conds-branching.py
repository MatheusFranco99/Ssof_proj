if(c>0) :
   a=b()
   if (c<3) :
      a=f(a)
   else :
      c=d(a)
e(a,c);

# tip: sources, sanitizers and sinks can appear inside branches, and they can be nested


c -> NON_INIT(c)
compare -> NON_INIT(c)

b() -> None
a -> NON_INIT(c)


a -> NON_INIT(c)
f(a) -> {A,f}, NON_init(c)
a -> {A,f}, NON_init(c)

a -> Non_init(c)
d(a) -> NI(c), {B,d}
c -> NI(c), {B,d} ++{B,d,c}

a -> NOn_init(c), {A,f}


c -> NOn_init(c), {B,d}
a -> Non_init(c), Non_init(a)
e(a,c) -> ++ {B,e,c}, {A,f,e},{B,d,e} {A,e,a}, {B,e,a}