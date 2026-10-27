# Managed server embedding

V2bX embeds listeners with one `constant.Tunnel` and one socket factory per
panel node. It does not start Mihomo's global client tunnel or controller.
The host must authorize and meter the authenticated `Metadata.InUser` on both
TCP streams and UDP packets; an outbound protocol is not necessarily a server
protocol.

`transport/socks5.ServerHandshakeWithReply` calls the optional reply allocator
after successful authentication and command parsing, before sending BND.ADDR
and BND.PORT. This permits a private UDP relay for each TCP association. The
host owns cleanup, source-address pinning, association expiry, and billing.
The original `ServerHandshake` remains available. Clients now reject nonzero
SOCKS REP codes, and servers reject an unoffered password method.

For TLS, `ca.NewTLSKeyPairLoaderForListener` consults the embedding socket
factory's optional `TLSKeyPairLoader` method. The host can authorize its exact
server key pair and reload it without changing Mihomo's global `SAFE_PATHS`.
Ordinary configuration files retain the existing path checks. Host loaders
must return immutable certificate snapshots and synchronize replacement.

ShadowQUIC's programmatic `PacketDialer` lets the host own JLS decoy sockets
separately from authenticated user traffic. It is excluded from YAML/JSON and
the inbound decoder. A nil callback keeps normal Mihomo tunnel routing.

Listener close flags use atomics. Inbound wrappers tolerate closing before a
successful listen, including typed nil interfaces after a failed constructor.
TrustTunnel tolerates already-closed UDP/TCP sockets after its service closes
them. Membership updates still require listener replacement where the SDK
does not expose a live user table; this change does not introduce mutable,
unsynchronized authentication maps.

Concurrent server regression tests also found unsynchronized AnyTLS stream
close errors and VLESS Vision read/write inspection state. Stream errors and
inspection flags now use atomics; TLS filtering uses a small mutex without
locking network IO. A late AnyTLS stream close hook runs exactly once.
