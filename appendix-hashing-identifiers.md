Key Lookup: Hashing Identifiers?
=====================================================================

Summary
---------------------------------------------------------------------
This document summarizes percieved advantages and disadvantages of 
requiring key queries (e.g. "Give me alice@example.com's key") to use
a hashed query (e.g. "Give me c160f8cc69a4f0bf2b0362752353d060's 
key").

Technical Difficulties
---------------------------------------------------------------------
According to RFC 2821, "The local-part of a mailbox MUST BE treated 
as case sensitive."  According to the rest of the world, email 
addresses are not case sensitive, and Alice@example.com is the same
mailbox as ALICE@example.com.  An email address would have to be
canonicalized before hashing.  Different langauges have different 
upper and lowercasing rules.

Mailservers allow users to specify arbitrary content after a 
metacharacter in their mailbox.  Most commmonly, example@gmail.com and
example+extradata@gmail.com deliver to the 'example' mailbox.  In 
other mailservers (such as qmail) the metacharacter is customizable, 
and is often '-'.  An email address would have to strip out any extra
data after the unknown (and thus guessed) metacharacter.

Percieved Gains
---------------------------------------------------------------------
There are few reasons one may wish to have key lookups done via 
hashed identifiers:

 1. Hashing provides an even distribution of address prefixes for
    load balancing.
 2. An adversary who observes the query does not learn the email
    address searched for.
 3. The provider may not wish to provide the key distributor with a
    list of all users in the system. Hashed identifiers allow 
    ambiguity in who the users are.
    
Enumeration
---------------------------------------------------------------------
An attacker wishing to enumerate users of a provider is neither
advantaged nor disadvantaged by the hashing.  While there is an 
additional computational cost, this is most likely marginal compared 
to the network transmit time.  An attacker must still guess the 
username, optionally putting it through the hashing algorithm,
and query the service.  Unlike NSEC/NSEC3 in DNS, the attacker is not
provided hashed or unhashed entries without guessing.

An adversary who is watching key queries does see less information
if the identifiers are hashed; however, key queries should be 
performed over a secure channel.  If the secure channel is 
compromised, an active attack is likely possible. 

Hashing key identifiers only protects the names of the addresses from
the key distribution server from enumerating the usernames. However,
the key distribution server gets to see every single user in the 
system (even if hashed) and is able to perform offline attacks 
against this database.  This is a stonger position than a remote
attacker, and the key distribution server is, by definition, a 
trusted piece of infrastructure.  

Conclusion
---------------------------------------------------------------------
Although defense in depth is certainly a recommended practice, hashed
identifiers requires several technical hurdles to be inellegantly 
worked around (with no one-size-fits-all solution) and does not 
provide significant gains in realistic scenarios.