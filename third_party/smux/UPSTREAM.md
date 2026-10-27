Vendored from github.com/metacubex/smux at
v0.0.0-20260105030934-d0c8756d3141. The upstream MIT license is included.

Local change: queued frames own their payload. writeFrameInternal can return
on timeout/close before sendLoop consumes the request; retaining the caller's
slice violated net.Conn.Write ownership and raced with TLS buffer reuse.
queue_ownership_test.go reproduces this deterministically.

This remains a separate Go module. Embedders must pin its replacement too;
Go does not inherit dependency replace directives. V2bX pins this submodule
and the Mihomo root to the same Git commit.

CI runs the race suite excluding the upstream 1 GiB / 8 GiB bulk transfer
stress tests, which exceed the three-minute CI bound under instrumentation.
Those tests remain available for a dedicated throughput run.
