package dns

import (
	"context"
	"errors"
	"net/netip"

	D "github.com/miekg/dns"
)

// publicIPClient is deliberately opt-in per nameserver. Doctor Mobile uses it
// only for public domestic-domain policies, never for arbitrary LAN/custom DNS.
// Validating here lets the parallel pool try another server before choosing a
// poisoned response; validating the winning response would already be too late.
type publicIPClient struct{ dnsClient }

// deferredDNSAnswer is a legitimate negative/alias-only reply. It must not beat
// a slower positive reply, but is still returned if no server has an address.
type deferredDNSAnswer struct{ msg *D.Msg }

func (*deferredDNSAnswer) Error() string { return "DNS reply has no requested address" }

var fakeIPv4Range = netip.MustParsePrefix("198.18.0.0/15")
var reservedIPv4Range = netip.MustParsePrefix("240.0.0.0/4")
var unspecifiedIPv4Range = netip.MustParsePrefix("0.0.0.0/8")

func isPublicDNSAddress(ip netip.Addr) bool {
	ip = ip.Unmap()
	return ip.IsGlobalUnicast() && !ip.IsPrivate() && !fakeIPv4Range.Contains(ip) &&
		!reservedIPv4Range.Contains(ip) && !unspecifiedIPv4Range.Contains(ip)
}

func wrapClientWithPublicIPFilter(c dnsClient, params map[string]string) dnsClient {
	if params["dm-public-ip"] == "true" {
		return publicIPClient{c}
	}
	return c
}

func (c publicIPClient) ExchangeContext(ctx context.Context, q *D.Msg) (*D.Msg, error) {
	msg, err := c.dnsClient.ExchangeContext(ctx, q)
	if err != nil || msg == nil || len(q.Question) != 1 {
		return msg, err
	}
	qtype := q.Question[0].Qtype
	if q.Question[0].Qclass != D.ClassINET || (qtype != D.TypeA && qtype != D.TypeAAAA) {
		return msg, nil
	}
	if msg.Rcode != D.RcodeSuccess && msg.Rcode != D.RcodeNameError {
		return msg, nil // Keep the pool's existing SERVFAIL/REFUSED handling.
	}
	usable := false
	for _, rr := range msg.Answer {
		var ip netip.Addr
		switch answer := rr.(type) {
		case *D.A:
			ip, _ = netip.AddrFromSlice(answer.A)
			usable = usable || qtype == D.TypeA
		case *D.AAAA:
			ip, _ = netip.AddrFromSlice(answer.AAAA)
			usable = usable || qtype == D.TypeAAAA
		default:
			continue
		}
		if !isPublicDNSAddress(ip) {
			return nil, errors.New("DNS public-domain policy rejected a non-public or fake address")
		}
	}
	if msg.Rcode == D.RcodeNameError || !usable {
		return nil, &deferredDNSAnswer{msg}
	}
	return msg, nil
}
