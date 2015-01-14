StarfishNet
===========

This is the StarfishNet protocol.  It is named for the neurological
independence of the limbs of a starfish from the rest of the animal;
nonetheless, the limbs and CNS visibly and functionally form part of a single,
coherent body.

StarfishNet works the same way.  Much as in other IEEE802.15.4-based wireless
sensor network protocols, there is a single coordinator node at the centre of
the network.  This coordinator has a solely administrative function: it serves
as the root of the routing tree (constructed similarly to ZigBee), makes
initial configuration decisions about the tree, and allocates network addresses
(which are also 802.15.4 short addresses) to its immediate children.

However, this is where the similarity ends.  Other network protocols ---
particularly ZigBee --- centralise security metadata at this same coordinator
node; this node is thus implicitly trusted by every other node on the network.
(Think Wi-Fi access points for a common example of the same problem.)  What if
we didn't?  What if the coordinator were just a bureaucrat, if security
associations were performed pairwise between nodes on the network without the
coordinator's involvement?

This means a quadratic number of key-agreement transactions --- which is fine
--- but also a potentially quadratic number of manual identity verifications
--- which is not.  But what if nodes could vouch for each other?  Especially if
that vouching could be context-sensitive?  Then, given associations between
nodes A and B, and B and C, A and C could set up a an association, with B
vouching for their identities, as long as they trust B to do so.  In fact,
there's nothing stopping B vouching for any property of A or C about which it
posseses relevant information.

StarfishNet provides the following services to higher layers:

* Authenticated key agreement and session establishment.
* Encrypted, integrity-protected transport.
* Reliable, in-order transport.
* Replay protection.
 
StarfishNet is designed with the following principles in mind:

* Public-key cryptography is expensive, but not forbidden. The number of
  public-key operations StarfishNet performs therefore needs to be minimised.
* Symmetric cryptography is cheap, as is hashing.
* IEEE802.15.4 packets are very small, so as much space as possible should be
  available to higher layers to transport actual data. (That is, StarfishNet
  should impose as little space overhead as possible.)
* Using the radio costs power. StarfishNet should therefore transmit as few
  packets as possible.

StarfishNet does not use IEEE802.15.4 link-layer acknowledgement, because it is
insecure.  Packet acknowledgement is instead done at the network layer.
Encrypted packets are acknowledged explicitly.  Packets in an association
transaction implicitly acknowledge each other.  Other unencrypted packets
should be acknowledged, but that functionality is so far unimplemented.

StarfishNet does not use IEEE802.15.4 link-layer encryption, because such
packets are not routable.  (This is a flaw in IEEE802.15.4; ZigBee exhibits the
same behaviour.)  The IEEE802.15.4 AUX header (used by link-layer encryption, and
reused by ZigBee for network-layer and application-layer encryption)
is also larger than the StarfishNet encryption header.

StarfishNet also does not implement broadcasts.
