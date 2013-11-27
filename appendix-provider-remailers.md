Reducing Metadata: Per-Provider Remailers
=====================================================================


Summary
---------------------------------------------------------------------
This document suggestions a technique to reduce metadata seen on 
inter-provider links.


Threat Model
---------------------------------------------------------------------
If alice@example.com emails bob@foocorp.com, it is assumed the 
adversary is able to see contents of the SMTP connection between 
example.com and foocorp.com.  

The adversary is not able to see the connection between Alice and 
example.com nor Bob and foocorp.com.  The adversary does not have a 
presence inside any of the providers.


Remailer
---------------------------------------------------------------------
In colloquial terms, a remailer is a service that will accept a 
message from a user encrypted to it's public key, decrypt it, and 
then re-mail it to the stated destination.  An adversary who observes
the mail sent from the user to the remailer, but cannot observe the 
remailer, does not learn who the intended recipient of the message 
was.


In UEE
---------------------------------------------------------------------
If a provider supports this feature, it signals in DNS that it 
accepts remailed messages at a specific mailbox, we will assume 
remailer@provider.com.

If a client or other provider supports this feature, they will 
perform the following steps when alice@example.com emails 
bob@foocorp.com.

Ordinary UEE steps
 1. Look up if foocorp.com supports UEE and their parameters
 2. Query for bob@foocorp.com's public key
 3. Perform optional Key Authenticity calculations on the key
 4. Encrypt the mail to bob@foocorp.com's key
Additional Remailer Steps
 5. Query for remailer@foorcorp.com's public key
 6. Perform optional Key Authenticity calculations on the key
 7. Place the ciphertext from Step 4 into an envelope format 
    containing Bob's address (bob@foocorp.com)
 7. Encrypt the envelope to remailer@foocorp's key
 8. Mail the resulting (twice-)encrypted message to 
    remailer@foocorp.com

Upon receipt, foocorp.com will automatically decrypt the message to
remailer@foocorp.com and retrieve envelope.  It will then behave as 
if it has recieved a message directly for Bob, and will either 
transmit the ciphertext for Bob (if he manages his own key) or will
decrypt it for Bob (if the provider manages the key.)


Security Gained
---------------------------------------------------------------------
The attacker, watching the SMTP link between example.com and 
foocorp.com know that an email was sent from some user at example.com
to some user at foocorp.com - but because of the remailed message,
no longer knows who is mailing who.  (Although they do learn timing 
and size information.)
    
    
Conclusion
---------------------------------------------------------------------
In the wake of widespread provider compromises and legal cooperation,
it is generally not reasonable to assume the adversary does not have
a presence inside a provider.  However, within the assumed threat 
model, we demontrate a technique to disguise metadata without 
incurring additional network latency or traffic.