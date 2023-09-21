---
title: "Opportunistic TCP-AO with TLS"
abbrev: "Opp-TCP-AO"
docname: draft-bonaventure-tcp-ao-tls-latest
category: exp

ipr: trust200902
area: Transport Area
workgroup: tcpm
keyword: Internet-Draft

stand_alone: yes
smart_quotes: no
pi: [toc, sortrefs, symrefs]

author:
 -
    name: Olivier Bonaventure 
    organization: UCLouvain 
    email: olivier.bonaventure@uclouvain.be
-
    name: Maxime Piraux
    organization: UCLouvain
    email: maxime.piraux@uclouvain.be
 -
    name: Thomas Wirtgen
    organization: UCLouvain
    email: thomas.wirtgen@uclouvain.be


normative:
  RFC5925:
  RFC8446:

informative:
  RFC4960:
  RFC6335:
  RFC7258:
  RFC8041:
  RFC8305:
  RFC8548:
  RFC8684:
  RFC9000:
  RFC7540:
  RFC3552:


--- abstract

This document specifies an opportunistic mode for TCP-AO. The TCP
connection starts with a well-known authentication key which is later
replaced by a key derived from a TLS handshake. 

--- middle

# Introduction


The TCP Authentication Option (TCP-AO) {{RFC5925}} provides integrity
protection for long-lived TCP connections. It assumes that the communicating
hosts share a Master Key Tuple (MKT). This MKT is used to derived traffic
keys that allow to authenticate the packets exchanged by the two hosts.
TCP-AO supports different authentication algorithms {{RFC5926}}.

TCP-AO protects the integrity of all the packets exchanged during a TCP
connection, including the SYNs. Such a protection is important for some
services, but many applications would benefit from the integrity protection
offered by TCP-AO, notably against RST attacks. Unfortunately, for many
applications that use long-lived TCP connections, having an existing MKT on
the client and the server before establishing a connection is a severe
limitation from a deployment viewpoint.

This document proposes a less secure version of TCP-AO where the packets
exchanged at the beginning of a connection are protected by default keys.
These default keys are replaced by secure keys derived from the TLS {{RFC8446}}
secure handshake to protect the integrity of all the other packets. This
prevents packet injection attacks that could result in the failure of TLS
connections.

This document is organised as follows. We provide a brief overview of
Opportunistic TCP-AO in section {{section}}. Then section {{tls}} discusses the
required changes to TCP-AO and TLS. 


# Conventions and Definitions

{::boilerplate bcp14-tagged}

## Notational conventions

This document uses the same conventions as defined in Section 1.3 of
{{RFC9000}}.

This document uses network byte order (that is, big endian) values.
Fields are placed starting from the high-order bits of each byte.

# An overview of Oppotunistic TCP-AO {#overview}

In a nutshell, an opportunistic TCP-AO connection starts like a TCP-AO
connection, i.e. the SYNs and all subsequent packets are authenticated,
but using a MKT with a default key. During the TLS secure handshake, the
communicating hosts derive secure keys and update their MKT with these
secure keys. Thus, the beginning of the connection is not protected against
packet modifications of packet injection attacks. The real protection only
starts once the TLS handshake finishes. The TLS Finished message, and
all subsequent TLS records, are protected with the secure traffic keys derived
from the TLS handshake.

Figure {{fig-overview-handshake}} illustrates the establishment of an
opportunistic TCP-AO connection. The client sends a SYN packet using
the default MKT defined in this document. The TCP-AO option in the SYN
packet uses a KeyID of 0. The server validates the TCP-AO
option and replies with an integrity protected SYN+ACK.
The client confirms the establishment
of the TCP-AO connection with an ACK and sends a TLS ClientHello. This
ClientHello contains the AO Extension defined in this document. This
extension specifies the authentication algorithms that the client wishes
to use for the connection and whether TCP options should be protected or
not. At this point the server can derive the TLS keys and the TCP-AO keys. 
The server replies with TLS ServerHello and TLS EncryptedExtensions
messages that are sent in packets using the default TCP-AO MKT. It installs
the new key in its TCP-AO MKT.
Upon reception of these messages, the client can derive the TLS and
TCP-AO keys. It installs the TCP-AO keys in its MKT and sends the Finished
message protected with the new MKT. All the packets exchanged after the
Finished are protected using the MKT derived from the secure TLS handshake.

~~~~~~~~~~~~~~~~~~~~~~~~~~~
Client                                   Server
 |                    SYN                    |
 |------------------------------------------>|
 |                  SYN+ACK                  |
 |<------------------------------------------|
 |       ACK, TLS ClientHello + ao           |
 |------------------------------------------>|
 |  TLS ServerHello, TLS EncryptedExtensions |
 |				 , ...       |
 |<------------------------------------------|
 |              [TLS Finished]               |
 |------------------------------------------>|
 |              [TLS records]                |
 |<----------------------------------------->|
~~~~~~~~~~~~~~~~~~~~~~~~~~~
{: #fig-overview-handshake title="Starting an opportunistic TCP-AO connection with TLS"}

# Opportunistic TCP-AO {#format}

## The AO TLS Extension

This document specifies one TLS extension to support the opportunistic
utilization of TCP-AO with keys derived from the TLS secure handshake.
The AO Extension can only be placed in the ClientHello message.


~~~
enum {
    AO(TBD),
    (65535)
} ExtensionType;
~~~

The format for the AO Extension is defined by:

~~~
   enum {
      tcp_option_protection_enabled(1),
      tcp_option_protection_disabled(2),	
      (255)
   } TCPAOOptionProt;

   enum {
      HMAC-SHA-1-96(1),
      AES-128-CMAC-96(2),	
      (255)
   } TCPAOAuth;

   enum {
      KDF_HMAC_SHA1(1),
      KDF_AES_128_CMAC(2),	
      (255)
   } TCPAOKDF;

   struct {
      TCPAOOptionProt prot;
      TCPAOAuth auth;
      TCPAOKDF kdf;
   } AOExtension;
~~~


The TCPAOOptionProt indicates whether the client requests integrity
protection for the TCP options or not. The TCPAOAuth specifies
the authentication algorithm defined in {{RFC5926}} that will be
used to protect the packets starting from the transmission of the transmission
of the Finished message. The TCPAOKDF specifies the key derivation
function defined in {{RFC5926}} and requested by the client to derive the
keys from the TLS Master Key.

## The initial MKT

To support the establishment of opportunistics TCP-AO connections, the
client and the server must be configured with a default MKT. This default
MKT is used to authenticate the packets until the derivation of the secure
MKT from the TLS Master Key. This document defines the following default MKT:

 - TCP connection identifier: selected by the TCP stack
 - TCP option flag. The default MKT assumes that TCP options are not included
   in the MAC calculation.
 - The current values for the SendID and RecvID are set to 0
 - The Master key is set to 0x1cebb1ff
 - The default key derivation function is  KDF_HMAC_SHA1
 - The default message authentication code is HMAC-SHA-1-96

## Derivation of the TCP AO MKT after the secure handshake

The Master key for the MKT to protect the TCP packets after the transmission
of the Finished messages shall be derived from TLS Master secret using:

~~~

  Derive-Secret(Master Secret, "tcpao", ClientHello...server Finished)
     = tcp_ao_secret
     
~~~


The traffic keys used by the client and the server can then be derived
from this Master key using the procedures defined in {{RFC5925}} and
{{RFC5926}}. 

The client and the server also need to decide on the key identifier
to use after having sent (for the server) or received (for the client) the
Finished message. This is a local decision of each host provided that they
select a different key identifier than 0. In the example below, the server
selects x as its key identifier while the client selects y.

TODO: on pourrait aussi utiliser le key identifier comme etant le nombre d'iterations du KDF

~~~~~~~~~~~~~~~~~~~~~~~~~~~
Client                                   Server
 |            SYN (KeyID=0, RNextID=0)       |
 |------------------------------------------>|
 |          SYN+ACK (KeyID=0, RNextID=0)     |
 |<------------------------------------------|
 |       ACK, TLS ClientHello + AO           |
 |          (KeyID=0, RNextID=0)             |
 |------------------------------------------>|
 |  TLS ServerHello, TLS EncryptedExtensions |
 |          (KeyID=0, RNextID=x)             |
 |<------------------------------------------|
 |              [TLS Finished]               |
 |           (KeyID=x, RNextID=y)            |
 |------------------------------------------>|
 |              [TLS records]                |
 |           (KeyID=y, RNextID=x)            |	
 |<----------------------------------------->|
~~~~~~~~~~~~~~~~~~~~~~~~~~~
{: #fig-handshake2 title="Usage of the KeyID and RNextID in TCP AO options during the establishment of an Opportunistic TCP-AO connection"}



## Key updates

What happens when TLS keys are updated ? Probably not needed to change the TCP-AO keys, they should be changed independently. Use key identifier as sequence number for the HKDF ?

# Security Considerations


To be provided

# IANA Considerations

To be provided.

# Acknowledgments
{:numbered="false"}

The authors thank xx for their comments on the first version of this draft and
Dimitri Safonov for the TCP-AO implementation in Linux. 

# Change log
{:numbered="false"}



