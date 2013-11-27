Reducing Metadata: Pooling Messages
=====================================================================


Summary
---------------------------------------------------------------------
This document suggestions a technique to reduce metadata seen on 
encrypted inter-provider links.


Threat Model
---------------------------------------------------------------------
If alice@example.com emails bob@foocorp.com, it is assumed the 
adversary is able to perform end-to-end traffic correlation, 
observing packet sizes and timing on the links between Alice and her
provider example.com, example.com and foocorp.com, and Bob and his
provider foocorp.com.

The adversary is not able to see the contents of any connection. The
adversary does not have a presence inside any of the providers.

In current email usage, an adversary who is thus empowered can see 
that Alice creates a connection to her provider example.com, and 
sends an amount of data. Her provider shortly thereafter connects to
foocorp.com and sends a similarly-sized amount of data. Foocorp.com
then sends a similarly-sized amount of data down an open IMAP link to
Bob.  The adversary observes these connections being made 
sequentially, and is able to learn with high probability that Alice 
has emailed Bob.


Mix Networks
---------------------------------------------------------------------
A Mix Network aims to frustrate traffic analysis by pooling messages
in each Mix Node.  A Mix Node will accept a number of messages from 
multiple recipients, and store them in a pool.  After certain 
criteria are met (number of messages, time elapsed) the Mix Node will
'flush' some or all of the messages in their pool, forwarding them to
their recipients.  An adversary observing identically-sized encrypted 
messages entering the pool should be unable to determine which 
message went to which recipient.

Pooling Algorithms dictate under what conditions the mix will 'fire',
or flush it's messages, and how it will choose the messages in the 
pool to send.  An overview of pooling algorithms is provided in
"From a Trickle to a Flood: Active Attacks on Several Mix Types"[0].

[0] http://freehaven.net/doc/batching-taxonomy/taxonomy.pdf


In UEE
---------------------------------------------------------------------
A provider accepts messages over an encrypted SMTP link. These may 
be messages on either side of the conversation: Alice sending the 
email, or Bob's provider accepting the email from Alice's. Before 
immediately delivering them to their recipients, it instead pools 
all incoming messages, delivering them only when it decides the pool
should fire.

Providers may choose pooling algorithms based on their security 
posture and usage scenarios.  Organizations not terribly concerned 
with privacy, or organizations that process hundreds of messages a 
minute, may operated a timed mix, firing in full every 30 seconds. 
Other organizations, recieving a small but steady stream of mail but
more concerned may operate a timed dynammic pool mix.

To address size-correlation-based attacks, interoperating providers
can request the sending communication partner to pad a message to
a certain byte length, perhaps determined by approximate buckets of 
messages the provider commonly seen.


Security Gained
---------------------------------------------------------------------
It is certain that in particular circumstances no security will be 
gained against a traffic confirmation attack - particurally with 
large email messages or attchments.  Likewise, the fairly 
innocuousness of spam messages make flushing attacks on mix nodes 
easy to conduct without raising suspicion.

It's unlikely that organizations will risk delaying email 
significantly for a debatable amount of security gained; however,
as no additional network latency is incurred, and the pooling 
algorithm is entirely within control of the provider, some security
can be gained and will raise the bar to successful traffic 
correlation.

    
Conclusion
---------------------------------------------------------------------
In a realistic threat model, where an adversary can observe some or
all of the mail links but is unable or unwilling to perform active 
attacks to peer inside the links, pooling algorithms introduce 
uncertainy on both ends of message transmission.  Providers remain in
control of the latency incurred by their users.