---
title: "Opportunistic TCP-AO with TLS"
abbrev: Opp-TCP-AO
docname: draft-piraux-tcp-ao-tls-latest
category: exp

submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: "Transport"
workgroup: "TCPM"
keyword:
 - tcp
 - tls
 - tcp-ao

venue:
  group: "TCPM"
  type: "Working Group"
  mail: "tcpm@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/tcpm/"
  github: "IPNetworkingLab/draft-tcp-ao-tls"

author:
 -
    name: Olivier Bonaventure
    organization: UCLouvain & WELRI
    email: olivier.bonaventure@uclouvain.be
 -
    name: Maxime Piraux
    organization: Unaffiliated
    email: maxime.piraux@uclouvain.be
 -
    name: Thomas Wirtgen
    organization: Unaffiliated
    email: thomas.wirtgen@gmail.com


normative:
  RFC5925:
  RFC5705:
  RFC8446:
  RFC5926:
  RFC8126:
  RFC5869:

informative:
   CONEXT24: DOI.10.1145/3696406
   RFC4253:
   I-D.hbq-bgp-tls-auth:
   I-D.wirtgen-bgp-tls:

--- abstract


This document specifies an opportunistic mode for TCP-AO when used with TLS.
In this mode, the TCP connection starts with a well-known authentication key
which is later replaced by a secure key derived from the TLS handshake.

--- middle

# Introduction


The TCP Authentication Option (TCP-AO) {{RFC5925}} provides integrity
protection for long-lived TCP connections. It assumes that the communicating
hosts share a Master Key Tuple (MKT). This MKT is used to derive traffic
keys to authenticate the TCP packets exchanged by the two hosts.
TCP-AO supports different authentication algorithms {{RFC5926}}.

TCP-AO protects the integrity of all the packets exchanged during a TCP
connection, including the SYNs. Such a protection is important for some specific
services, but many applications would benefit from the integrity protection
offered by TCP-AO, notably against RST attacks or injection attacks that can
happen later in the connection. Unfortunately, from a deployment viewpoint,
for many applications
that use long-lived TCP connections, having an existing MKT on the client
and the server before establishing a connection is a severe limitation.

This document proposes a way to derive a MKT from the TLS secure handshake {{RFC8446}}.
Before the TLS handshake completes, this document defines default keys which
offer a limited protection to the first TCP packets of the connection.
These default keys are then replaced by secure keys to protect the integrity of
subsequent packets past the TLS handshake. This
prevents packet injection attacks that could result in the failure of the TLS
connection.

This mechanism can be used to authenticate the TCP packets of BGP sessions when TLS
is used as discussed in {{CONEXT24}},{{I-D.hbq-bgp-tls-auth}},{{I-D.wirtgen-bgp-tls}}.

This document is organised as follows. We provide a brief overview of
Opportunistic TCP-AO in section {{overview}}. Then section {{format}} discusses the
required changes to TCP-AO and TLS.


# Conventions and Definitions

{::boilerplate bcp14-tagged}

## Notational conventions

This document uses network byte order (that is, big endian) values.
Fields are placed starting from the high-order bits of each byte.

# An overview of Opportunistic TCP-AO {#overview}

In a nutshell, an opportunistic TCP-AO connection starts like a TCP-AO
connection, i.e. the SYNs and all subsequent packets are authenticated,
but using a MKT with a default key specified in this document.
Then, during the TLS handshake,
both endpoints announce the parameters they will use for their MKT. When the
TLS handshake completes, they both can securely derive an MKT from the
TLS secrets and use this new MKT to protect subsequent packets.
Thus, the beginning of the connection is not protected against
packet modifications and packet injection attacks. The real protection only
starts once the TLS handshake finishes.

Figure {{fig-overview-handshake}} illustrates the establishment of an
opportunistic TCP-AO connection. The client sends a SYN packet using
the default MKT defined in this document. The TCP-AO option in the SYN
packet indicates the use of this default MKT. The server validates the TCP-AO
option and replies with an integrity protected SYN+ACK.
The client confirms the establishment
of the TCP-AO connection with an ACK and sends a TLS ClientHello containing
the AO Extension defined in this document. This
extension specifies the authentication algorithms that the client will use when
sending TCP packets on the connection and whether TCP options will be protected.
At this point the server can derive from the TLS keys the TCP-AO keys to use
for validating clients packet.
The server replies with TLS ServerHello and TLS EncryptedExtensions
that are sent in packets protected with the default TCP-AO MKT.
To finish the setting up of TCP-AO, the server includes the AO Extension in
the sent EncryptedExtensions to announce the parameters it will use to
protect the packets it will send.
It then derives the new key and installs it in its TCP-AO MKT.
Upon reception of these messages, the client can derive the TLS and
TCP-AO keys. It installs the TCP-AO keys in its MKT and sends the Finished
message protected with the new MKT. All the packets exchanged after the
Finished message are protected using the MKT derived from the secure TLS handshake.
The initial TCP-AO key remains available on the client and server to support
retransmissions until the derivation of the next key (K_2).

~~~~~~~~~~~~~~~~~~~~~~~~~~~
Client                                   Server
 |            SYN (KeyID=0, RNextID=0)       |
 |------------------------------------------>|
 |          SYN+ACK (KeyID=0, RNextID=0)     |
 |<------------------------------------------|
 |       ACK, TLS ClientHello + AO           |
 |          (KeyID=0, RNextID=0)             |
 |------------------------------------------>|
 |  TLS ServerHello, TLS Enc.Extensions + AO |
 |          (KeyID=0, RNextID=x)             |
 |<------------------------------------------|
 |              [TLS Finished]               |
 |           (KeyID=0, RNextID=0)            |
 |------------------------------------------>|
 |   [K_1 installed and promoted on server]  |
 |   [K_1 installed and promoted on client]  |
 |              [TLS records]                |
 |           (KeyID=1, RNextID=1)            |
 |<----------------------------------------->|
~~~~~~~~~~~~~~~~~~~~~~~~~~~
{: #fig-overview-handshake title="Starting an opportunistic TCP-AO connection
with TLS. The messages between brackets are authenticated using the TCP-AO MKT
derived from the TLS handshake."}


The TCP-AO can be changed during the lifetime of the TLS session. To derive
a new TCP-AO key, this document uses the HKDF-Expand construction {{RFC5869}}.


# Opportunistic TCP-AO {#format}

## The TCPAO TLS Extension

This document specifies one TLS extension to support the opportunistic
utilization of TCP-AO with keys derived from the TLS secure handshake.
The extension is used by endpoints to specify the parameters of the MKT
they will use to protect the TCP packets they send.

~~~
enum {
    tcp_ao(TBD),
    (65535)
} ExtensionType;
~~~

The format for the "tcp_ao" extension is defined by:

~~~
   enum {
      tcp_option_protection_disabled(0),
      tcp_option_protection_enabled(1),
      (255)
   } TCPAOOptionProt;

   enum {
      HMAC-SHA-1-96(0),
      AES-128-CMAC-96(1),
      (255)
   } TCPAOAuth;

   enum {
      KDF_HMAC_SHA1(0),
      KDF_AES_128_CMAC(1),
      (255)
   } TCPAOKDF;

   struct {
      TCPAOOptionProt prot;
      TCPAOAuth auth;
      TCPAOKDF kdf;
   } TCPAO;
~~~


The TCPAOOptionProt indicates whether the endpoint will protect the integrity
of TCP options or not. The TCPAOAuth specifies
the authentication algorithm defined in {{RFC5926}} that will be
used to protect the packets. The TCPAOKDF specifies the key derivation
function defined in {{RFC5926}} and that the endpoint will use to derive its
keys. If the peer did not use this option when initiating the TLS session, this
document assumes the following default:

 - no integrity prototection for the TCP options
 - The default key derivation function is KDF_AES_128_CMAC
 - The default message authentication code is AES-128-CMAC-96


## The initial MKT

To support the establishment of opportunistics TCP-AO connections, the
client and the server must be configured with a default MKT. This default
MKT is used to authenticate the packets until the derivation of the secure
MKT from the TLS keying material. This document defines the following default MKT:

 - TCP connection identifier: selected by the TCP stack.
 - TCP option flag. The default MKT assumes that TCP options are not included
   in the MAC calculation.
 - The current values for the SendID and RecvID are set to 0.
 - The Master secret is set to 0x1cebb1ff.
 - The default key derivation function is KDF_AES_128_CMAC.
 - The default message authentication code is AES-128-CMAC-96.

Given that the TCP-AO KeyID is a local field and has no global meaning,
hosts have no guarantee that a KeyID of 0 will be unequivocally recognised as
designating the default MKT specified in this document.
{{Section 7.5.1 of RFC5925}} indicates that hosts receiving SYN segments with
TCP-AO enabled and no matching MKT should remove the option and accept them.
A client initiating a TCP connection in the opportunistic mode of TCP-AO
MUST check that the server accepted the use of TCP-AO in this mode by replying
using the default MKT before deriving a secure MKT as described in this
document.

## Derivation of the first TCP AO MKT (K_1)

The Master key for the MKT to protect the TCP packets after the transmission
of the Finished messages are derived from the Exporter Master Secret using
Keying Material Exporters {{RFC5705}}:

~~~
struct {
   TCPAO ao;
   uint8 key_id;
} TCPAOKeyExporterContext;
~~~

~~~
TLS-Exporter("tcp-ao", TCPAOKeyExporterContext, 32)
   = tcp_ao_secret
~~~

The TLS-Exporter function receives the label "tcp-ao", with the parameters of
the MKT and the KeyID as context as defined in the TCPAO structure within
{{the-tcpao-tls-extension}}. It generates a 32-byte secret.


In this document both endpoints use the same value for SendID and RecvID.
Implementations MUST use SendID = RecvID for each MKT derived from the
TLS Exporter and for each subsequent ratchet step. The value 0 is reserved for the
default MKT; derived KeyIDs MUST be in the range 1–254.

The client and server can decide the value of the KeyID independently and
announce it in the AO TCP Option as defined in {{RFC5925}}.
The KeyID MUST be different than the default KeyID of 0.

The traffic keys used by the client and the server can then be derived
from this secret using the procedures defined in {{RFC5925}} and
{{RFC5926}}.

After K_1 is installed and promoted as the send key, the initial MKT (K_0) is retained as
a receive-only fallback to allow the peer's in-flight TLS Finished to be retransmitted as
it may still carry K_0 authentication.
K_0 is deleted when the first HKDF ratchet step installs K_2 (see Section 4.4).
At any moment exactly two MKTs coexist: the current send key and the previous key kept
as a receive fallback.

After K_1 is installed, the client and server stop using the
initial MKT defined in {{the-initial-mkt}}.

## Periodic Key Rotation {#rekey}

After K_1 is installed, endpoints rotate to a new MKT periodically using an
HKDF ratchet. Each rotation derives the next key from the current one using
HKDF-Expand {{RFC5869}}:

~~~
  K_{n+1} = HKDF-Expand(
      PRK  = K_n,
      info = "tcp-ao-rekey",
      L    = 32 octets,
      Hash = SHA-256
  )
~~~


Key rotation can be done using a two-phase timer with period T (the configured rekey
interval):

**Phase 1** (timer fires, `rotating = false`):

  1. Delete K_{n-1} (delayed-delete: K_{n-1} is kept as a receive
     fallback since the previous rotation).
  2. Derive K_{n+1} = HKDF-Expand(K_n, "tcp-ao-rekey", 32).
  3. Install K_{n+1} on the socket without promoting it as the send key.
  4. Set `rotating = true`. Schedule Phase 2 after delay T.

**Phase 2** (timer fires, `rotating = true`):

  1. Promote K_{n+1} as the send key.
  2. Set `rotating = false`. Schedule next Phase 1 after delay T.

The one-interval gap between Phase 1 and Phase 2 gives the peer time to
complete its own Phase 1 and install K_{n+1} before either side starts
sending segments authenticated under K_{n+1}.

KeyIDs cycle in the range 1–254. Reuse of a KeyID is safe because each
reuse carries a distinct ratchet-derived secret.

Keys that are not anymore in use SHOULD be wiped out of memory after each HKDF_Expand..

# Security Considerations

TCP-AO provides a protection against the injection of TCP RST. This can impact
legitimate connectionless resets, e.g. when an endpoint loses the required state
to send TCP-AO segments. {{Section 7.7 of RFC5925}} provides recommendations to
mitigate this effect.

Using TCP-AO with TLS can also inhibit the triggering of the "bad_record_mac"
alert that abruptly closes the TLS session when a decryption error occurs. For
instance, injected packets will fail the TCP-AO authentication and be ignored
by the receiver instead. This also prevents sessionless resets at the TLS level,
and similar recommendations to {{Section 7.7 of RFC5925}} can apply.


The ratchet state MUST be wiped when the session closes.

# IANA Considerations

IANA is requested to create a new "Opportunistic TCP-AO with TLS" heading for
the new registries defined in this section. New registrations under this heading
follow the "Specification Required" policy of {{RFC8126}}.

IANA is requested to add the following entries to the existing "TLS
ExtensionType Values" registry.

| Value | Extension Name | TLS 1.3 | Recommended | Reference     |
|:------|:---------------|:--------|:------------|:--------------|
| TBD   | tcp_ao         | CH, EE  | N           | This document |

Note that "Recommended" is set to N as this extension is intended for
uses as described in this document.

IANA is requested to create a new registry "Authentication Algorithms" under
the "Opportunistic TCP-AO with TLS" heading.

The registry governs an 8-bit space. Entries in this registry must include a
"Algorithm name" field containing a short mnemonic for the algorithm. Its
initial content is presented in {{the-tcpao-tls-extension}} in
the TCPAOAuth enum. The registry has a "Reference" column. It is set to
{{RFC5926}} for the two initial algorithms.

IANA is requested to create a new registry "Key Derivation Functions" under
the "Opportunistic TCP-AO with TLS" heading.

The registry governs an 8-bit space. Entries in this registry must include a
"Key Derivation Function name" field containing a short mnemonic for the function. Its
initial content is presented in {{the-tcpao-tls-extension}} in
the TCPAOKDF enum. The registry has a "Reference" column. It is set to
{{RFC5926}} for the two initial functions.

# Acknowledgments
{:numbered="false"}

The authors thank Dimitri Safonov for the TCP-AO implementation in Linux.
The authors thank Michael Tüxen, Yoshifumi Nishida and Alessandro Ghedini for
their questions and comments on the document during the TCPM meeting at IETF 118.


# Change log
{:numbered="false"}



