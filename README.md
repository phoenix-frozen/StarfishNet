StarfishNet
===========

This is the Starfish protocol.  Named for the neurological independence of the
limbs of a starfish from the rest of the animal; nonetheless, the limbs and CNS
visibly and functionally form part of a single, coherent body.

StarfishNet works the same way.  Much as in other 802.15.4-based wireless
sensor network protocols, there is a single coordinator node at the centre of
the network.  This coordinator has a solely administrative function: it
allocates 802.15.4 short addresses to its children (individually if they are
RFDs, in blocks if they are FFDs).  It also serves as the root of the routing
tree, which is also constructed in the same way as with ZigBee.

However, this is where the similarity ends.  Other network protocols centralise
security metadata at this same coordinator node; this node is thus implicitly
trusted by every other node on the network.  (Think Wi-Fi access points for a
common example of the same problem.)  What if we didn't?  What if the
coordinator were just a bureaucrat, if security associations were performed
pairwise between nodes on the network without the coordinator's involvement?
We'd have a handshake problem, that's what.  On a wireless sensor network,
where nodes routinely want to talk to each other, we have a quadratic number of
handshakes being performed, each of which requires manual verification to
ensure no man-in-the-middle attacks.  But what if nodes could vouch for each
other?  What if associations between nodes A and B, and B and C, meant B could
vouch for A in respect of C, and vice-versa?  Only insofar as B knows anything
about them, of course.  But if it's only their identities we're seeking to
guarantee, that might just be enough.  Assuming A and C trust B to vouch for
that property.

StarfishNet does not use 802.15.4 MAC-layer acknowledgements, because they are
insecure.  It reimplements acknowledgement at the network layer for encrypted
packets.  Packets in an association transaction implicitly acknowledge each
other, so there's no need to do it explicitly.  Other unencrypted packets
should be acknowledged, but there is, as yet, no implementation of this.

StarfishNet also does not yet implement broadcasts.
