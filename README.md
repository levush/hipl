# hipl
This is a clone of hipl-1.0.8 made from trunk checked out at 20.04.17
from Launchpad using bzr checkout lp:hipl

hipl does not get too much attention from its original maintainers,
so I decided to play around with it and learn some c.

hipl implements the very cool host integrity protocol which allows for
overlay routing using "IPv6" adresses, called hit which are derived from
a public key of the peer.
Only peer who have the corrosponding private key are able to communicate
"as" a given hit.
So generating x509 certs using a CA, one can generate a very secure network,
without spoofing attacks that allows for overlay routing forming a "next generation"
network.

Also there is openhip which I included also on my github account
look at levush/openhip


look at the ietf it has some interessting rfcs and also work group papers
about hip.

RFC 4423 and RFC5201 are a good start.
HIP uses IPsec with BEET mode, which is supported by the linux kernel's
IPSec implementation.

Have fun with hip

levush

