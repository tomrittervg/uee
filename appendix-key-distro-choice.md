Key Distribution: DNS or ...?
=====================================================================


Summary
---------------------------------------------------------------------
This document summarizes the advantages and disadvantages of 
distributing user keys in DNS and HTTP.


Keys in DNS
---------------------------------------------------------------------
If a sender wished to e-mail alice@example.com, the sender would 
query the DNS of the recipient's provider with a DNS query something 
like the form `encrypt.alice._uee.example.com` which would return the
recipient's public key, or NXDOMAIN if there was no public key.

When verifying a signature, the MUA would look up 
`sign.alice._uee.example.com` which would return the signing key.

Because we want to be able to support publication of multiple
concurrent signing keys (to allow for smooth key transitions)
older/deprecated keys can also be fetched at:
 * `1.sign.alice._uee.example.com`
 * `2.sign.alice._uee.example.com`
 * ... (decimal prefixes)

Once `N.sign.alice._uee.example.com` returns NXDOMAIN, there are no 
more keys published.  

DNS has a well understood deployment model and a well understood
caching model.  It is lightweight and fast, and can be secured with
DNSSEC.  It is capable of redundancy.

Additionally, DNSSEC provides protection against blocking. NSEC and 
NSEC3 records prevent an adversary from blocking access to a server,
and users being unsure if that service exists. 

However, there are scenarios where DNS is not confidential.  If an
adversary watches the network traffic of a sender (whether the sender
is an end-user or a provider) they will be able to observe a DNS
request for a specific recipient in the recipient's domain.  Even 
when the sender uses DNSSEC, the problem remains because DNSSEC 
queries provide Authenticity and Integrity, but not Confidentiality.  
This leaks the specific recipient, whereas in a mail exchange that 
takes place inside an TLS tunnel, no such leak takes place.

Additionally, there are a number of providers (companies, normal
domain administrators included) who outsource their e-mail to a third
party - but still manage their own DNS.  They enter MX records for 
the mail provider - but in a DNS-deployment model they would have to 
enter public keys themselves or set up a potentially complicated 
delegated DNS tree.  This delegated subtree is not supported by many 
DNS providers and would be another engineering effort required.


Keys in HTTPS
---------------------------------------------------------------------
If a sender wished to email alice@example.com the sender would 
perform a DNS(SEC) query to the recipient's domain, looking up a SRV 
record for `_uee._tcp.example.com`.  If the result is NXDOMAIN, then 
the recipient does not support UEE.  However if the recipient does 
support UEE, the response will be a list of servers and ports.

Using those servers and ports (taking `keys.example.com` and port 443
as an example) the sender will issue a HTTP request, secured using
TLS, to a URI of the form
`https://keys.example.com/com/example/%40/alice/encrypt`.  That
response makes use of standard HTTP response codes.  A 200 OK will
include recipient's public key.  A 404 Not Found would indicate a user
does not have a public key, and encryption should not be performed.

When verifying a signature, the MUA does the same SRV lookup, and then
requests `https://keys.example.com/com/example/%40/bob/sign` For prior
signing keys:
 * `https://keys.example.com/com/example/%40/bob/sign.1`
 * `https://keys.example.com/com/example/%40/bob/sign.2`
 *  ... (decimal suffixes)
 
Once .../sign.N returns a 404, there are no more keys published.

Deploying HTTPS servers as the targets of SRV records is a well
understood deployment model, and organizations have a solid
understanding of deploying webservers, maintaining them, making them
redundant, enabling caching, and distributing data using Content
Distribution Networks.  Fetching HTTPS content is a common task, it is
reasonably fast and lightweight.  

An adversary can block access to the key distribution servers. But 
because the keyservers are discovered over DNSSEC, they are protected
against an attack where the adversary blocks access to the key 
distribution servers in an attempt to prevent a user from knowing a 
provider uses UEE. The user is certain the provider supports UEE, and 
can conclude that the servers are either nonfunctioning or blocked.

When directly examining the HTTPS mechanism in comparison to the
confidentiality leaks in the DNS mechanism, HTTPS fares much better.
In this scenario, the network observer is able to learn that the
sender is discovering a key for a user at the recipient's provider,
but not the individual user(s) who will receive the mail.  

The recipient's provider is also disclosed; however, because the 
sender's provider is about to make a connection to it in the 
upcoming SMTP connection - so this leak is no worse than what we
have currently IF we assume the attacker can monitor both the sender
and the sender's provider.  If the attacker is only able to monitor 
the sender, then this does leak information.  Tooling around
end-user mail clients should work to mitigate this risk: key caching,
keyring syncing (perhaps using the sender's provider), and proxied 
key lookups come to mind.

The HTTPS key discovery mechanism lends itself well to current web
architecture and services.  Organizations are capable of setting DNS
SRV records once, and managing individual user changes is less of a
headache.  It is relatively easy to deploy static HTTP servers with 
standard filesystem-permissions for scoping key management. Users 
could be given direct write access to their own keys, and one key 
distribution hub could host key publication for many domains, 
potentially giving each domain admin privileges over their 
subdirectories.

Conclusion
---------------------------------------------------------------------
DNS and HTTPS-based Key Distribution systems both allow hierarchical
data, redundancy models, and caching. They can both provide some 
degree of authenticity through public root authorities.  

However, DNS-Based key distribution systems leak more information 
relative to HTTPS-based key lookups.  Additionally, managing DNS 
entries for each user of a service does not lend itself to the 
current sale and management of DNS today.

HTTPS-Based key distribution systems leak less information 
comparitively, and does not suffer the same management issues.