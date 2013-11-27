UEE: Toward Ubiquitous Encrypted E-mail
=======================================

Glossary
---------------------------------
Throughout this document, we try to use the following phrases with 
specific meanings.

* User: the end user and/or the end user's MUA

* Email provider: a service provider that operates a DNS domain or 
    subdomain, the key directory, and serves users

* Sender: the application or service that encrypts and then sends 
    an email. This may be a provider or a user

* Recipient: the application or service that receives an email and 
    decrypts it. Again, the provider or user

* Sending user: the user sending an email

* Receiving user: the user receiving an email

* Key Directory: the service operated by an email provider to allow 
    senders to retrieve keys for the provider's users 
   (we avoid "keyserver" to eliminate confusion with OpenPGP/HKP)

* Trust Root: a root of trust that keys may chain to for an 
    assurance of authenticity. This root may be a provider-operated
    root or a single/set of externally operated Certificate 
    Authorities

* Key Authenticity: for a given e-mail address, whether the sender 
    believes that the key belongs to the e-mail address.


Existing Problems & Hard Problems
---------------------------------

E-mail is still mainly sent in the clear, despite many years of work
on the problem.  By comparison to HTTPS (which nearly every person who
browses the web uses regularly), most people who use e-mail cannot
send or receive an encrypted message.

The lack of uptake of e-mail encryption is a multi-faceted problem.
Certainly the tooling we have today is lacking - it is often confusing
to users and does not work seamlessly with all the ways users expect
to be able to work with their e-mail: on desktop clients,
browser-based webmail, mobile devices, tablets, and all manner of
devices.

However there are also very difficult problems in this space that have
no silver bullet.  If you'd like to e-mail a recipient you've never
corresponded with before - how do you retrieve their public key and
how do you know it's authentic?  How do you know if they even have a
public key or if someone is merely blocking you from retrieving it?
If you'd like to manage your e-mail on multiple devices, how do you
deal with Key Management?  How do you revoke a key that's been
compromised?  How do you communicate this revocation to your peers?
How do you send multi-recipient e-mails or mails to a mailing list?

These problems are all exceptionally difficult ones that cannot be
easily solved in a vacuum or by writing more code.  We feel these
issues must be addressed head-on for any e-mail encryption solution to
gain traction.  Iterative development of the standards we have now is
virtually non-existent because the relative paucity of users makes it
difficult to allocate design and engineering resources to improving
the tools.  The existing tooling discourages uptake even by users who
might have a strong need for the functionality.

Rather than iterative development of existing tools, we propose to 
tackle the hardest problems directly.  We describe a unified mechanism
for Key Discovery guidelines and minimum standards for Key 
Authenticity, a standard for revocation, and existing standard mail 
transport mechanics.

With these issues solved, focus can move to the facets of the problem
relating to tools and user operation.  We propose a radical step to
provide email encryption for the masses: accept that the provider will
manage the secret key material for most users, make ciphertext
transparent to the user, and surface user interface enhancements to
show authentic and confidential messages.

For users who wish to manage their own key, and face the difficulties 
of Key Management themselves, we recognize our current e-mail encryption 
tools are harder to use than they must be for widespread adoption.  
If we can address the above difficult problems in the space, we can 
improve the deployment base of encrypted e-mail.  This will encourage 
and justify the development of better end-user tools.

XXX - we should review http://www.gaudior.net/alma/johnny.pdf and
      integrate from that

XXX - Also work with other examples of clear->secure transitions.
      telnet->ssh, http->https
   
Key Discovery
-------------

Key Discovery is the act of taking an e-mail address and determining
confidently the user's public key or determining that the user does
not have a public key. A Key Discovery mechanism must:

 * have a well-understood deployment model
 * have a well-understood caching mechanism
 * be light-weight and fast
 * be capable of redundancy
 * Provide at least the same level of confidentiality currently
   expected of normal e-mail usage

### HTTPS

In this mechanism a sender will perform a DNS(SEC) query
to the recipient's domain, looking up a SRV record for
`_uee._tcp.example.com`.  If the result is NXDOMAIN, then the recipient
does not support UEE.  However if the recipient does support UEE, the
response will be a list of servers and ports.

Using those servers and ports (taking `keys.example.com` and port 443
as an example) the sender will issue a HTTP request, secured using
TLS, to a URI of the form
`https://keys.example.com/com/example/%40/alice/encrypt`.  That
response makes use of standard HTTP response codes.  A 200 OK will
include recipient's public key.  A 404 Not Found would indicate a user
does not have a public key, and encryption should not be performed.
For more information about the key and message transport format see
Section YYY.  For Key Authenticity concerns see Section YYY.

When verifying a signature, the MUA does the same SRV lookup, and then
requests `https://keys.example.com/com/example/%40/bob/sign`

Because we want to be able to support publication of multiple
concurrent signing keys (to allow for smooth key transitions)
older/deprecated keys can also be fetched at:

 * `https://keys.example.com/com/example/%40/bob/sign.1`
 * `https://keys.example.com/com/example/%40/bob/sign.2`
 *  ... (decimal suffixes)

Once .../sign.N returns a 404, there are no more keys published.  MUAs
should probably be advised to limit their key retrieval to no more
than a few keys.

XXX - Can the signing key or headers or other metadata include dates
      for which the key was valid, to limit the MUA lookup?

HTTPS-based Key Lookup MUST use at least HTTP/1.1 with the Host header
and TLS with the SNI extension.

Keys MAY be cached by the sender, and the recipient's Key Directory
uses standard HTTP headers to indicate how long the sender may cache
the key for.  XXX - This needs to be stated very explicitly including
which of the many caching headers we're talking about =)

Deploying HTTPS servers as the targets of SRV records is a well
understood deployment model, and organizations have a solid
understanding of deploying webservers, maintaining them, making them
redundant, enabling caching, and distributing data using Content
Distribution Networks.  Fetching HTTPS content is a common task, it is
reasonably fast and lightweight.  The largest concern comes from X.509
Certificate validation errors.  The potential for validation to fail
is discussed in Section YYY.

Additionally, the HTTPS key discovery mechanism also makes it
relatively easy to deploy static HTTP servers with standard
filesystem-permissions for scoping key management. Users could be
given direct write access to their own keys, and one key distribution
hub could host UEE key publication for many domains, potentially
giving each domain admin privileges over their subdirectories.


XXX - What are the implications of using CDNs for this?

XXX - For the HTTPS discovery mechanism, we should probably define a
      hierarchical system of paths within a domain so that if a
      provider wants to use a simple filesystem, it will still work
      with 60K keys without exhausting filesystem limits of files.
      dkg: Is this necessary?  symlinks also don't count against the
      subdir limit (since they don't increment the link count of the
      parent dir) so an admin who wants to deploy large domains in
      this way (larger than 32K on ext3, larger than 64K on ext4
      without dir_nlink) could just create their own layout and
      symlink to the proper location.
      tjr: Dunnoe.  It was a thought I had.  Didn't realize the 
      symlinks trick.

Signaling Provider-Level Information in DNS
-------------------------------------------

As mentioned in Key Discovery, UEE is signaled at a provider level by
placing information into DNS.

### Data Conveyed

The following pieces of data are conveyed:

 * This provider is UEE is enabled (Required)
 * The server(s) and port(s) for the Key Directory (Required)
 * The operating mode: Report-Only or Enforcement (Required)
 * A preference for validating keys of users of the provider
   (Optional)
   * Two options are defined: "Trust Root" and "Web of Trust"
 * The specific root or set of roots permissible for Trust Root
   validation, including all intermediate certificates (Optional)
 * A failure reporting mechanism (Optional)
 
### UEE Enabled && Key Directory Location

If a provider has one or more SRV records returned from
`_uee._tcp.example.com` - this indicates the provider is UEE enabled.

### Operating Mode, Key Validation, Trust Root, Failure Reporting

TBD XXX

For Explanations of their meanings, see Section YYY: Operating Modes 
and Failure Reporting and Section YYY: Key Authenticity: Additional 
Key Authenticity Calculations.


Benefits
--------

It's undeniable that implementing and deploying UEE will require a 
significant amount of effort. What are the benefits of migrating?  
In an ecosystem where mail contents, but not conversation partners 
or patterns are encrypted - what will we gain, and how is it better 
than moving all SMTP links to STARTTLS?

There are large tracts of society who by all rights SHOULD use
encrypted email for the security of their clients.  Doctors, Lawyers,
individuals operating at Defense Contractors, National Infrastructure, 
Finance, Credit Card Companies - the list continues.  All of these 
industries have sensitive and valuable information that is worth stealing, 
and that have been targeted and successfully compromised by sophisticated 
actors.  By and large these industries do not use email encryption.  
If these companies' email contents were encrypted, it would be no easier 
for attackers to obtain sensitive data, and in the case where mailservers 
were accessed or domains transparently hijacked - it would be significantly 
more difficult.

In rare cases, some companies do use a centrally managed e-mail 
encryption gateway.  Interfacing with such a gateway is extremely 
difficult for individuals outside the company. A ubiquitous solution, 
implementing open standards for both message transport and Key Discovery, 
will allow easy interoperation between companies and between companies and 
consumers. Security will not be siloed inside individual organizations, 
but span them.

While DKIM signatures validate that a message was sent from a domain, 
it does not support and does not intend to support verification of an 
individual sender within a domain, or historical validation of messages.  
If a server has rotated its DKIM keys, all DKIM signatures made with the 
older key will fail. With UEE, recipients are able to validate the 
origin of messages to the sender, and validate its authenticity 
historically.  Receiving an e-mail from your lawyer is different from 
receiving an e-mail from the lawyer's billing department. 

XXX - Triple Check claims here.

XXX - Additionally, the signature may be attached to the message, allowing 
      you to validate it wherever you obtain the message.
      tjr: Actually, not really. PGP Inline messages do travel with the 
      message, but S/MIME or PGP/MIME do not.  We'd have to specify a
      container format similar to PGP Inline to support the use case of
      "See a message in a list archive and know it's valid."
      dkg: actually inline PGP doesn't do this either with most
      web-based archives, since most of them mangle formatting, and inline
      PGP has a bunch of other problems; web-based message archives
      would need to offer direct retrival of unmodified RFC-822 style
      messages to enable this feature to work.

While today's complex spam-fighting mechanisms work well, UEE signatures 
will augment them to provide another data point to determine if this 
email should be considered valid.  IP Reputation-based systems have been 
used extensively for IPv4 addresses, and now can be expanded for use in 
email on a per-domain (DKIM) and per-user (UEE) basis.  

XXX - This needs improvement. With DKIM, there's no reason you can't 
      do this now. DKIM ensures no one sent the email but the domain
      and if you know that for certain it's easy to just say "the From
      address is valid because no one lets people send mail as another
      user".  

Currently, a small minority of users do jump through the hoops needed to
operate encrypted email. For those users, UEE represents a vast expansion of
the number of users who can receive encrypted email.

XXX - Technical Arguments here.



Key Enrollment
--------------

Although UEE allows individual receiving users to opt out of e-mail
encryption - as will likely be necessary initially for system
accounts, bespoke applications, and other scenarios - the intention is
for every user to have a key and opt-outs be exceptions.

### Non-Human Associated Addresses

Generally speaking, there is no reason that an e-mail address not
associated with a human cannot also make use of UEE.  E-mails encrypted
to such a receiving address would have a key managed by the provider,
and messages decrypted before being handed off (via standard POP,
IMAP, MAPI/RPC, etc) to the mechanism that
uses the message currently. Shared mailboxes (such as those used by
customer service representatives) can also have a key managed by the
provider, and the individuals who work with the shared mailbox will be
operating on decrypted messages.  However, if for legacy or
interoperability purposes an e-mail address cannot process encrypted
messages, it is acceptable for the address to lack a key and thus
receive unencrypted, legacy messages.

### Enrollment Process 

The enrollment process can be generally stated in terms of the following steps:

 0. Placing UEE indicators into DNS (Done once per domain, not per-user)
 1. Account Creation
 2. Key Generation
 3. Key placed in Key Directory

The coupling of these steps is largely dependent on the existing
mechanism of account creation.  We walk through several scenarios and
explain how the steps may be coupled or effected.
 
#### Internet Service Provider, Internet Mail Provider, Large Corporations

It is assumed that large corporations, ISPs, and Internet Mail
Providers have an existing mechanism to create a user and e-mail
address.  After placing the UEE indicators into DNS, including the
location of the Key Directory, such an entity is ready to implement
UEE.  Upon e-mail address creation such as the employee onboarding
process, sign-up for online e-mail, or a customer account creation, the
provider SHOULD (MUST? XXX) generate a cryptographically secure
keypair for the user, and explicitly retain the secret key.  This key
is registered in the Key Directory.

#### Hosted e-mail

In a hosted e-mail scenario, an entity (we will use a small company as
an example) controls their own DNS, but places MX records that point
to a third party hoster that processes the small company's e-mail.  In
this scenario, the small company must decide if they wish to use a
similar service for their Key Directory.  For now, we will assume the
third party hoster will also operate the Key Directory for the small
company, for example by having the small company designate an A/AAAA
record of a subdomain (keys.example.com) to the third party hoster's
existing Key Directory.  The use of SNI (in TLS) and the Host header
(in HTTP) allows the third party hoster to operate multiple companies'
directories on shared hardware.  The small company will place the UEE
indicators into DNS, in the same manner that they place the MX records.

XXX do we want to mandate that the Key Directory's host name must be
    within the DNS zone of the domain being looked up?

When the small company uses its control panel to create a new user
account, the third party hosting the small company's e-mail MAY
generate a cryptographically secure key for the user if the company
administrator has instructed it to do so (perhaps by default).  The
small company administrator MAY have a mechanism to extract the
secret key from the third party hoster.  Similarly the small company
administrator MAY have a mechanism to upload the user's public/secret
keypair to the third party hoster.  Finally, to round out the options,
the small company administrator MAY have a mechanism to upload only
the public key.

In the final case outlined above - a new option for e-mail hosting has
been opened up.  The small company may wish to contract the e-mail
operation to a third party for the purposes of more reliable uptime
for receiving external e-mails, but not trust them with the contents of
the email.  In this case, they may operate their own e-mail gateway
that contains the secret keys for its employees.  In this case
downtime of the small company-administered gateway prevents their
employees from sending or checking their mail - but does not prevent
the rest of the internet from sending e-mail to the small company.

If in fact the small company wishes to run their own Key Directory,
they must interface with the third party hoster to extract and place
public keys into the directory, upload the public keys to the third
party hoster, or otherwise sync them in another manner.  This scenario
is complicated, and its merits are debatable, but it is possible to
do.

#### .forward 

It is fairly common for a server to run a local mailserver, in which
case its local user accounts are the users capable of receiving e-mail.
This server may or may not be attached to a privately or publicly
routed domain name.  It is common in this scenario for a user to have
a `.forward` file that will have their e-mail forwarded to another
address.

In this scenario, the server may or may not operate UEE server or
client components.  If it does not operate a UEE server component, all
mail received will not be encrypted.  If it does not operate a UEE
client component, the forwarded mail will not be encrypted, even if
the forwarding address supports UEE.

If the server does operate a UEE server component, there is no
standard mechanism for keys to be loaded into the server's Key
Directory - indeed, merely operating the Key Directory is left
undefined, although it can be accomplished with a standard webserver.

If the server operates both a UEE server and client component, and it
contains the user's secret key, it should decrypt the message, fetch
the key of the forwarding destination address, encrypt it to the key if it is
found, and forward the message.  If the key found is identical to the
public key of the user the server knows about, it SHOULD NOT decrypt
the message, and merely pass the message on.  In this case, the server
may not even have the secret component of the key - a user has a
single key they have configured to be used for multiple e-mail
addresses.  This scenario is explicitly supported.

If the serer operats only a UEE client component, and the forwarding
destination address has a key, it should encrypt all mail that it
receives before forwarding.

XXX what should a forwarding server do with mail that it finds itself
    unable to decrypt, but appears to already be encrypted to the
    destination key?

#### Shared Hosting Use Case

It is common for smaller websites to be operated on a shared hosting
platform, and administered through a web control panel such as cPanel
or Plex.  If the shared hosting provider registers the domain name
also, it can populate the UEE information in DNS.  If it does not, the
user will need to fill in the UEE information (provided by the hosting
provider) in the same manner the user must fill in the A/AAAA/MX
records.

When administering the shared hosting via the control panel, it is
expected that adding user e-mail inboxes and forwarding accounts will
create a keypair also, and load it into the Key Directory.

### Key Escrow Opt-Out

In many of the cases outlined - such as Internet Service Provider,
Internal Mail Provider, Corporation, and Hosted e-mail - a user MAY be
allowed by policy and implementation to upload the public component of
a keypair they control.  In this situation, the provider is unable to
decrypt incoming messages for the user, and by necessity must show and
send them encrypted messages over all the mechanisms they access their
e-mail.  This may include webmail, POP, IMAP, Exchange (XXX), and
directed to a mobile device.  The user must sign messages on the local
device, as the provider is unable to sign messages for the user.

In this scenario, a user is in charge of secret key management which
includes backing up the key and copying it to all devices they wish to
read encrypted mail or send signed mail from.  It also prevents the provider from
providing certain services to the user, such as server-side search of
messages, more effective spam filtering, enhanced keyword detection
(such as meeting invitations or directions), other services that rely
on parsing the content of the message, or allowing access from
unprovisioned devices.  Similarly, it prevents the provider from
performing actions that may be extremely relevant or required by the
provider, such as E-Discovery Case Management and virus scanning.

Generally speaking, we do not expect most corporations to allow this
action by policy, but do expect ISP and Internet Mail Providers to.
Likewise, we do not expect most users will use this option, as it
requires a good deal of technical sophistication today to move keys
between devices safely and it does limit a user's flexibility in ways
many users may not like.  The User Experience of this mode is outlined
in more detail in Section YYY.

### User/Key Enumeration

The Key Directory by necessity contains public keys for all or most
e-mail accounts.  If operated off a standard webserver, a Key Directory
SHOULD NOT enable directory listings, as this would provide a complete
list of existing users.

Even with Directory Listings disabled, a request for the key for an
account will tell an attacker performing user enumeration whether or
not an e-mail account exists.  The server MAY return keys for users
that do not exist to frustrate such an attacker, however returning an
invalid public key may be detected mathematically (depending on
algorithm XXX), generating fake public keys on demand is
computationally expensive, and reusing fake keys can be detected.

XXX - We need to justify this risk better, or re-mediate it somehow.
      It's faster than BOUNCEs but maybe that can be used to justify it?

Key Authenticity
----------------

A longstanding problem in any cryptosystem is how to establish
authenticity of a public key.  Traditionally, the three primary
mechanisms have been establishing trust via an out-of-band mechanism,
the X.509 Certificate Authority system wherein trusted third parties
certify keys, and the OpenPGP Web of Trust system, which establishes
key validity by building a path from trusted certifiers to the target.
UEE allows multiple mechanisms to establish the authenticity of a
retrieved key.  These mechanisms can be chosen based on the sender's
preference.  As before, the sender is defined as the entity that is
doing the encryption operation, whether this is an e-mail provider or
an end user's MUA.

### Base Key Authenticity

As explained in Key Discovery, keys are retrieved over via a HTTP
request to a TLS-secured website.  The X.509 certificate for the website
MUST be verified using either the Certificate Authority system OR via
a TLSA record retrieved over DNSSEC (which may include the Certificate
Authority system as well).  A key retrieved over this mechanism has
validity rooted in either DNSSEC or a Certificate Authority.  A sender
MAY improve the robustness of this verification by using standards of
securing HTTPS connections: primarily Public Key Pinning if the target
domain supports it.  Other options may include a system such as
Perspectives or Convergence. Attempting to use a Trust-On-First-Use
system is extremely likely to cause unacceptable failures when the X.509
certificate rotates and the sender has not updated the cache.

A key retrieved over the above mechanism has a base level of
authenticity. For an adversary to place a malicious key into the
directory, they would be required to either compromise the key
directory, a Certificate Authority, or the DNS (including the DNSSEC
key) of the recipient's provider.  UEE keys SHOULD be cached by Key
Directory clients for a period of time, which establishes a system of
Trust on First Use (or Pinning?  XXX).  The details of caching and
refreshing keys is detailed in Section YYY of Key Retrieval.

### Additional Key Authenticity Calculations

Additional mechanisms of key authenticity can be applied.  Two
mechanisms are defined in this document: individual keys MAY be signed
by a Trust Root or MAY be certified via the OpenPGP Web of Trust.

Other mechanisms may be devised and used.  An e-mail provider MAY
specify that it is their intention for all of its users' keys to be
validated via one of these mechanisms.  This is explained in Section
YYY.

A sender MAY apply these authenticity calculations even if the receiving provider
has not specified their intention to support or encourage such
calculations.  These additional, optional calculations MAY result in
different user interface considerations.  They SHOULD NOT prevent the
delivery of messages.

#### Trust Root Calculation

A key may chain to a domain-specific trust root.  This root may be operated by the
provider, analogous to the DANE Use Case 3 (name & link XXX).  This
root may also be an externally operated Trust Root, such as a public
Certificate Authority.  The root may also be a set of roots, such as
several permissible Certificate Authorities.

XXX https://tools.ietf.org/html/draft-ietf-dane-smime
XXX DANE use cases: https://tools.ietf.org/html/rfc6394
XXX DANE certificate usages https://tools.ietf.org/html/rfc6698#section-2.1.1

#### Web of Trust Calculation

A key may be validated or rejected after building a path from the
sending user's key to the key of the receiving user.  This path is
calculated based on trust decisions made explicitly by the sending
user (as opposed to the sender), although this calculation may be done
by the sending user's provider if the user has communicated those
trust decisions to the provider.

Generally speaking, the Web of Trust of today has seen limited use,
and building paths is not always possible.  Accordingly, it is most
appropriate for users who are knowledgeable about the mechanisms of
establishing key authenticity.

A provider may indicate its desire for its users' keys to be validated
by the Web of Trust (Section YYY) but cannot provide an assurance that
its users' keys will actually be able to be validated by this
mechanism because it cannot predict the sending user's trust decisions.

#### Alternate Mechanisms of Trust Calculation

Although we define only two methods of calculation, it is possible for
a key to be validated by other mechanisms, such as mechanisms relying
on the consensus of network perspectives.

### Dealing with Authentication Calculation Failures

Introducing multiple mechanisms for Key Authenticity calculations does
complicate the system.  Significant engineering effort is required to
implement any cryptosystem, and introducing N authenticity algorithms
multiplies this effort by a factor much larger than N. Furthermore,
when multiple algorithms exist, it must be explicitly defined what
happens when the algorithms give different results. We attempt to
resolve these conflicts.

In Section YYY we define what must happen when an operator attempts to
retrieve a key and cannot establish a trusted TLS connection to the
Key Directory.  This section only deals with keys that have already
been retrieved.

If a trust calculation results in a failure, but the calculation was
an optional calculation performed by the sender, the sender MUST NOT
send a failure report to the provider, even if the recipient has
enabled Failure Reports (Section YYY).

#### Trust Root Failure

An e-mail provider may have specified their intention that keys of its
users be certified via a Trust Root or a sender may choose to attempt
additional validation via a Trust Root. In this case, several failures
may occur:

 * The sender may not be able to build a path from key to Trust Root due to missing certificates
 * The sender may not be able to build a path from key to Trust Root due to invalid signatures
 * The path built by the sender may be invalid due to expired or revoked certificates
 * certificates in the path may not be valid for their position in the chain (e.g. path or length constraints)

A key certification error as a result of a failed Trust Root
calculation MAY allow the e-mail to be encrypted and sent regardless of
of the failure. An e-mail provider MAY or MAY NOT allow the user to
approve this course of action. (We expect a corporation to prevent a
user from overriding it.) A sender MAY send the message regardless of
failure without exposing the error to the user. The policy SHOULD be
available for the end user to review and MAY be customizable.
Generally speaking any behavior in this case is acceptable, as long as
the end user is able to know for certain what action will be taken in
what situation.

If a key certification error occurs as the result of a Trust Root
calculation error, and the provider of the recipient has enabled
Failure Reports (Section YYY) the sender SHOULD (MUST? XXX) send a
failure report to the provider.

#### Web of Trust Failure

An e-mail provider may have specified their intention that keys of its
users be certified via the Web of Trust. As mentioned earlier, a
provider cannot be certain its users' keys' authenticity will in fact be validated as
a result of the Web of Trust.  If a sender cannot verify the
recipient's key via a Web of Trust calculation, the user SHOULD (MUST?
XXX) be informed, and the e-mail MAY still be sent.  Generally
speaking, we expect Web of Trust calculations to be performed in
end-user MUAs and used only by users who are knowledgeable about the
mechanisms of establishing key authenticity.

If a key is rejected as the result of a Web of Trust calculation,
the sender MUST NOT send a failure report to the receiving user's
provider, even if failure reporting is enabled. Web of Trust
calculations are based on the sending user's personal trust decisions
and these must not be conveyed beyond the sender.


#### Alternative Authenticity Mechanism Failures

If a sender performs an alternate method of key authenticity
calculation, or combines key authenticity mechanisms, this calculation
and the steps taken when it fails SHOULD (MUST? XXX) be available for
the end user to review.

Key Rotation & Key Revocation
-----------------------------

Keys retrieved via the established Key Discovery mechanism are cached
according to the standard HTTP caching mechanisms - defined explicitly
in Section YYY.  This section covers Rotation and Revocation.

### Key Rotation

A provider is able to rotate a user's encryption key by publishing a
new record in /encrypt.  If the provider has possession of it, they
MUST retain the secret key material until they are confident no
further incoming e-mails will be encrypted to the old key.

A provider rotates a user's signing key by pushing all old signing
keys down one digit, and publishing the new key in /sign.  Secret key
material does not need to be retained if the old signing key is being
retired.

### Key Revocation

Key Rotation is the standard practice for keys revoked for
non-security reasons: if a key is too old, a new machine is being
commissioned, old secret key material accidently destroyed, etc.  Key
Revocation is necessary if the secret key material is believed or
known to be compromised.

XXX - what's the best approach?  If they're using a Trust Root - CRLs?
      OCSP?  What if they're not?  Low caching values?  Reinvent CRLs
      for each provider?

Message Format
--------------

So far, widespread encrypted e-mail (if what we have currently can be
called widespread) has been deployed with one of three message
formats: S/MIME, Inline PGP, and PGP/MIME.

Ultimately, all systems provide similar features: encryption of the
body of the e-mail, signature of the message, and delivery to multiple
recipients.  All systems also have similar limitations: lack of
encryption of the subject and other message headers.

Inline PGP suffers a few particular additional limitations: the
character set is not integrity protected (allowing an adversary to
change it and potentially effect an attack), attachment filenames are
(generally) not encrypted, and signatures are often invalidated by
MTAs that perform line wrapping or other message modification.

Comparing PGP/MIME and S/MIME the primary distinguisher is that S/MIME
has robust, native implementation in major MUAs including Microsoft
Outlook, Outlook Express (check XXX), Windows Live Mail (check XXX),
Lotus Notes (check XXX), Thunderbird, Evolution (check XXX), Apple
Mail (check XXX), the iOS e-mail client, and (more? XXX).  Inline PGP
and PGP/MIME is available in actively-maintained extensions and
plugins for Thunderbird (Open Source) and Outlook (Proprietary), as
well as much lesser used MUAs such as Mutt.

Considering the desire to have a great deal of inter-operation in
clients and servers to provide ubiquity, it is more desirable to use
S/MIME to bootstrap off the significantly larger market penetration of
that standard.

### S/MIME Considerations

Although S/MIME is preferable, it certainly will not fit the UEE model
precisely.  Changes required to it are still being researched and
evaluated. XXX

### Message Packaging

Although the exact mechanism is still undetermined, certain extra 
fields will be able to be contained in the encrypted and signed 
portions (in both or in only the signed portion).  These fields MAY
be displayed in User Agents that handle them, and will be ignored in
User Agents that cannot.  

Specifically, we envision at least the following specific fields:

  Encrypted Subject: Because mail subjects are sent in cleartext,
    this would be an optional encrypted subject that replaces the
    cleartext subject once decrypted.
    
  Encrypted-To Key: This is the key identifier the message was 
    originally encrypted to, signed by the sender. This reduces the
    ability for a provider to lie about a user's key.
    
XXX: Add other headers we want covered.  Or, add a generic "Replace
all headers you see with these headers" section.
    
Additionally, it may be possible to provide per-user future symmetric
keys to be used in later email, allowing Forward Secrecy.  This 
extension is left to later work.

Operating Modes and Failure Reporting
-------------------------------------

A provider MUST operate UEE in one of two modes: Report Only Mode and
Enforcement Mode.  Additionally, a provider MAY accept failure reports
from senders.

A trend in security mechanisms being developed is to provide a
report-only, non-enforcement mode to prevent the possibility of
rendering a website or service unusable. Two examples of such security
mechanisms are Content Security Policy and Public Key Pinning.  A
Report-Only mode allows a UEE compliant sender to do everything *but*
the encryption process to see if it would succeed.

Although it adds a large amount of complexity, A Report-Only mechanism
avoids a "Flag Day" for a provider where they flip a switch and just
*hope* that they haven't bricked e-mail for all their users.  Instead
they launch in Report Only mode, and collect failure reports to see if
things wouldn't work, and then fix them.

### Report Only Mode

A provider may signal in the DNS that all steps of UEE encryption
should be performed, except the actual encryption of the body - this
mode is known as Report Only mode.  In this mode, a sender will
attempt to fetch the key for a user and perform any additional trust
calculations signaled by the recipient's provider. If these steps are
successful, the sender MUST NOT encrypt the message and MUST include a
header in the message to inform the receiver of a successful UEE
operation.  This header is defined as:

`UEE: status=success; keyid=00112233445566778899AABBCC`

This header is also present in Enforcement mode, and has the same
parameters. Two parameters are defined initially.

 * keyid: the fingerprint of the public key the message would be encrypted to.
 * status: success or failure 

XXX - This needs to be specified, but:
 * need a registry for parameters
 * need to define that vendor/provider prefixes can be applied and custom parameters added
 * receivers should ignore parameters they do not recognize 
  
XXX - This needs to be ABNF-ed and such.

A provider SHOULD check incoming messages for the UEE header,
particularly the status parameter, and especially if it is operating
in Report-Only mode.  If after a period of deployment in Report Only
mode, multiple other providers are interoperating well, with no
failure statuses - the provider can move to Enforcement mode with
confidence.

### Enforcement Mode

In this operating mode, a provider has signaled that all steps of UEE
should be performed, including the final encryption of the message.  A
sender MUST include the UEE header as specified in Report Only mode
(Section YYY).

### Failure Reporting

A provider MAY indicate that it wishes to receive detailed information
about failures senders encounter when attempting to perform UEE
operations.  This failure reporting mechanism SHOULD be used in place
of adding these details to the UEE header.

Several failures may occur:

 * The recipient's provider's Key Directory may be unreachable
 * The recipient's provider's Key Directory may have an X.509
   certificate that cannot be validated by either a Certificate
   Authority or a TLSA record
 * The recipient's key may not be found in the Key Directory
 * The recipient's key, retrieved from the Key Directory, may be
   malformed
 * The recipient's provider may have specified an additional trust
   calculation that was unable to succeed (A generic error, of which
   specific ones are defined)
 * The recipient's provider may have specified a Trust Root but the
   sender was unable to build a path from key to Trust Root due to
   missing certificates
 * The recipient's provider may have specified a Trust Root but the
   sender was unable to build a path from key to Trust Root due to
   invalid signatures
 * The recipient's provider may have specified a Trust Root but the
   path built by the sender may be invalid due to expired or revoked
   certificates
 * The recipient's provider may have specified a Trust Root but the
   path built by the sender may be invalid due to certificate
   constraints that could not be satisfied (e.g. path length or name
   constraints)
 
If a failure occurs, and the recipient's provider has indicated it
wishes to receive failure reports, the sender SHOULD send a report.
The report is a JSON body that is POST-ed to the endpoint specified.
This endpoint may be accessible over HTTPS, and if so should provide an
X.509 certificate validated by a Certificate Authority or a TLSA record.

Because the failure reporting mechanism itself may suffer problems, if
the sender encounters an X.509 certificate validation error when
connecting it MAY ignore the error and POST the error regardless.  In
this event, the sender SHOULD follow-up with a failure report
regarding the certificate validation failure.

XXX - This will need way more work

The failure report should be of the following format:

```
{
      'datetime' : string containing ISO-whatever date and time of error
    , 'provider-policy' : //The sender's view of the information provided via DNS
        {
              'UEE-enabled' : true
            , 'key-directory' : 'https://keys.ritter.vg'
            , 'operating-mode' : 'enforcement' or 'report only'
           [, 'validation-preference' : '...' ]
           [, 'trust-root-data' : '...' ]
           [, 'report-uri' : '...' ]
        }
    , 'recipient-address' : 'tom@ritter.vg'
    [, 'recipient-key' : '...' ] //If the recipient key was retrieved, include it here
    , 'failure-type' : integer describing the type of failure, from the registry 
    , 'failure-description' : a provider-specific string describing the failure
    [, 'key-directory-certificate-path' : ... ] //If the Key Directory Certificate Validation failed, include the certificate path 
    [, 'additional-data' : 
        {
            //provider specific additional data they wish to include
        } ]
}
```




Tool Use / .01% Tools 
---------------------

If a User has opted out of the Key Escrow option, they have committed
to managing their own e-mail encryption and signing keys.  In this
situation, e-mail decryption and message signing must always occur on
the client's computing device.  As covered in Section YYY: Message
Format, existing S/MIME deployment is encouraging. Although UEE by
necessity will require some changes in the spec, this engineering
effort can be reused.


In this section we briefly cover what we feel must be developed or
improved in the various environments we currently e-mail.  Generally
speaking, we feel the allure of sending encrypted e-mail universally to
recipients will spur the development of tools and programs designed to
operate with UEE.

### Web Browsers

Traditionally, the most problematic arena for e-mail encryption has
been browser-based webmail. There are two primary reasons webmail has
proved problematic, both of them technical: trust concerns about the
provider taking active steps to subvert the user's key ownership and
the lack of a consistent API for a third party program to pull
structured data (e.g. MIME parts) out of the webmail interface.

#### Trust in webmail provider

A user with a non-escrowed key is in the unusual situation of trusting
their provider for a considerable number of things, including
providing UEE and providing a reliable Key Directory. They are also
vulnerable to traffic analysis of correspondents, subjects, date and
times.  However they are attempting to prevent the provider from
reading the message contents.  If we draw the line at message
contents, there are several components we must be concerned with in
webmail.

One concern relating to trust is the provenance of the code performing
the encryption and signing.  If this code is loaded from the provider
on each load, it could be changed without knowledge to the user.  This
change can be innocuous, but it could also be changed to subvert the
cryptographic operations.  Ideally speaking, the cryptographic code,
and all code it relies on, would be verified and unable to change
without notice to this user.  Today, this is accomplished with a
browser extension.

Another concern is where the compose textfield is rooted.  In webmail,
this compose textfield is of course rooted in the Document Object
Model (DOM) of the provider.  However, if a user with a non-escrowed
key were to use this compose field, the unencrypted message would be
available to the DOM of the provider, and thus could be read by the
provider.  The solution to this situation has been to override or
replace the compose textfield with one from the browser extension.  In
this situation, the provider is unable to access to field, as it is
part of the extension's DOM, not the provider's.  However, this is
significantly limiting, as providers often go to considerable length
to create compose textfields with advanced editing features.  These
would have to be duplicated in the extension, or the user must go
without.

#### API Churn

In the browser extensions we have seen so far for encrypted e-mail
access in webmail, a recurring problem has been how to specify the
DOM elements that contain relevant information: the encrypted message
to decrypt, the recipients to perform key lookup on, and other fields
as needed.

So far, most webmail providers have not had an incentive to provide a
consistent naming convention for these DOM elements to aid extension
writers.

#### Future Development

If UEE is developed and deployed, we expect webmail providers to
provide an API or microformat that allows reliable access to e-mail
messages from a browser extension.  We do expect browser extensions to
be the path forward, because of the Trust Issues inherent in any
non-extension solution.

### Mobile Devices

Mobile clients communicate with a server using a mail protocol such as
POP, IMAP, or Exchange (XXX MAPI?).  If a user does not manage their own
secret key, all encryption, decryption, and key lookups will be
performed on the server.  Although these clients may be enhanced to
provide indicators about whether or not an e-mail being sent will be
encrypted, or if an e-mail being received was encrypted - it is not
required for these clients to operate under UEE with no modifications.

If a user does manage their own secret key, and has configured the
device with it, all cryptographic operations, key lookups, and other
operations must happen on the mobile device.  Certain mobile mail
clients, such as iOS' native e-mail client, support S/MIME.  This
bootstraps them in terms of implementing the remainder of UEE.

### Desktop Clients

Desktop clients communicate with a server using a mail protocol such
as POP, IMAP, or Exchange (XXX MAPI?).  If a user does not manage their own
secret key, all encryption, decryption, and key lookups will be
performed on the server.  Although these clients may be enhanced to
provide indicators about whether or not an e-mail being sent will be
encrypted, or if an e-mail being received was encrypted - it is not
required for these clients to operate under UEE with no modifications.

If a user does manage their own secret key, the encryption,
decryption, key lookups, and all other operations must happen on the
client. This is a considerable amount of development effort; however,
three of the most popular desktop clients: Outlook, Lotus Notes (?
XXX), and Thunderbird all support S/MIME e-mail.  This does bootstrap
them to a certain degree in terms of development effort needed.
 
### Programmatic Access

The number of scripts and programs that send or receive mail must
number in the hundreds of thousands if not more.  However, most of
these applications still communicate with a server using a standard
mail protocol: SMTP, POP and IMAP most commonly.  If the server manages the
key for the program, the encryption, decryption, and other operations
will again be transparent to the program.

Library support for S/MIME exists, and we expect some amount of
library support for UEE to be developed, so it will of course be
possible for the program to manage the keys and cryptographic
operations itself.  This adds a considerable deal of complexity to a
custom application or script that may not be actively maintained.
Generally speaking, we expect programs or scripts in this category to
let the server manage the key.
 
### Server Support

The largest investment of development must be done on mail servers.
Servers such as Microsoft Exchange, Postfix, qmail, and the like must
be enhanced to do transparent encryption and decryption of messages as
they are received, as well as key lookup, and optionally trust
calculations.  We expect this to require a considerable amount of
investment on behalf of their authors.

Single Points of Failure
------------------------

In this situation, we identify several points of failure in the search
for a key that may cause unrecoverable downtime for individuals
attempting to interact with a provider who has enabled UEE.  All of
these examples have recommendations or requirements that apply only to
Enforcement mode.  In Report Only mode the failure SHOULD be reported
to the recipient's provider (if they have enabled Failure Reporting)
and mail delivery continue as normal.

### DNS Failures

If a sender queries the recipient's provider to query if they support
UEE or not, and the DNS does not answer at all, mail could not be
delivered anyway, as MX+A/AAAA records could not be retrieved.

If a sender queries the recipient's provider to query if they support
UEE or not, and the DNS answers for MX+A/AAAA records but not the UEE
information, this is a strange case as a NO RECORD (XXX) should be
returned instead.  In this case the sender MAY fail open and send
messages unencrypted.  This is an exceptionally dangerous scenario;
however, as an attacker can block these plaintext DNS requests.  

DNSSEC SHOULD (MUST? XXX) be used to provide authenticated NO RECORD
(XXX) responses. For resolvers that do not support DNSSEC, a provider 
SHOULD set a long TTL on the UEE record (we suggest 1 month (XXX)) 
and senders SHOULD cache this information locally - this pins UEE 
on the domain.

### Key Lookup Failures

If a sender knows a provider uses UEE, but cannot definitively
retrieve a key or a 404 response for a user, the key lookup has
failed.  This failure may be the result of network outage, network
interference, or an outage or misconfiguration of the recipient's key
directory.

This also is an exceptionally dangerous scenario, as an attacker can
block traffic to a Key Directory (which has a public IP address) in an
attempt to force the e-mail to be sent unencrypted.  We suggest
(require? XXX) senders handle this situation in the same manner as if
a mailserver was not responding - that is the sender SHOULD NOT send
the message in plaintext, and instead SHOULD queue the message for later key
lookup, encryption, and delivery.  This introduces a point of failure;
however, the recipient domain has opted in to UEE and understands that to
receive mail its Key Directory must maintain the same standard of
uptime as its mailservers.

XXX This advice concerns transient network outages and server outages
    - but not deliberate network interference.  If an operator of a
    network explicitly blocks access to the Key Directory of the
    recipient's provider no amount of retrying will allow the mail to
    be delivered.  This level of network interference is inherently
    malicious, and should be treated as such.  Unencrypted mail
    delivery SHOULD NOT occur, and manual investigation to confirm the
    censorship SHOULD occur.  General purpose network tools such as
    SSH tunneling and VPNs can be employed, as well as specialty
    applications designed to bypass censorship, such as Tor, Lantern,
    and XXX

If the recipient's provider has enabled Failure Reporting, the sender
SHOULD send a failure report to the recipient's provider.

### Key Authentication Failures

If a provider has indicated they intend senders to the domain use an
additional Key Authenticity calculation, this step may fail.  In this
scenario, the key already has some degree of authenticity, as it was 
retrieved from the key directory over a connection rooted in a DNSSEC 
chain or a Certificate Authority. The sender MAY send the message, 
encrypted to the key, regardless of the key authenticity failure, 
based on the sender's policy.  This is covered in more depth in Section 
YYY.

If the recipient's provider has enabled Failure Reporting, the sender
may send a failure report to the recipient's provider.  The scenarios
in which the sender should or should not send the report are covered
in Section YYY.

Combatting Common Problems
--------------------------

Several problems have been exposed in other cryptographic email 
schemes. UEE addresses these problems up-front. (XXX Haha not yet we 
don't.)

XXX - Complete this

### Content Modifications

https://en.wikipedia.org/wiki/DomainKeys_Identified_Mail#Content_modification

### E-Mail Annotations

Free Mail Providers, Mailing lists, and Central Antivirus add 
annotations to messages
https://en.wikipedia.org/wiki/DomainKeys_Identified_Mail#Annotations_by_mailing_lists

Perhaps we could add unsigned MIME components with specific types for the
common ones like "Legal Footer", "Mailing List Footer", and "Provider Footer"

### Character Sets

XXX