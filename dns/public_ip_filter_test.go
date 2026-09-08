package dns

import (
	"context"
	"net"
	"testing"
	"time"

	D "github.com/miekg/dns"
)

type publicFilterTestClient struct {
	ip    string
	rcode int
	cname bool
	delay time.Duration
}

func (publicFilterTestClient) Address() string  { return "mock-no-network" }
func (publicFilterTestClient) ResetConnection() {}
func (c publicFilterTestClient) ExchangeContext(ctx context.Context, q *D.Msg) (*D.Msg, error) {
	if c.delay > 0 {
		timer := time.NewTimer(c.delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	r := new(D.Msg)
	r.SetReply(q)
	r.Rcode = c.rcode
	if c.cname {
		r.Answer = append(r.Answer, &D.CNAME{Hdr: D.RR_Header{Name: q.Question[0].Name, Rrtype: D.TypeCNAME, Class: D.ClassINET}, Target: "target.example.ir."})
	}
	if c.ip != "" {
		ip := net.ParseIP(c.ip)
		if q.Question[0].Qtype == D.TypeAAAA {
			r.Answer = append(r.Answer, &D.AAAA{Hdr: D.RR_Header{Name: q.Question[0].Name, Rrtype: D.TypeAAAA, Class: D.ClassINET}, AAAA: ip})
		} else {
			r.Answer = append(r.Answer, &D.A{Hdr: D.RR_Header{Name: q.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET}, A: ip})
		}
	}
	return r, nil
}

func TestPublicIPPoolPrefersSlowerUsableAnswer(t *testing.T) {
	for _, tc := range []struct {
		name string
		bad  publicFilterTestClient
	}{
		{"private", publicFilterTestClient{ip: "10.0.0.1"}},
		{"loopback", publicFilterTestClient{ip: "127.0.0.1"}},
		{"fake", publicFilterTestClient{ip: "198.18.1.2"}},
		{"nxdomain", publicFilterTestClient{rcode: D.RcodeNameError}},
		{"nodata", publicFilterTestClient{}},
		{"cname_only", publicFilterTestClient{cname: true}},
		{"cname_fake", publicFilterTestClient{cname: true, ip: "198.18.1.2"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := new(D.Msg)
			q.SetQuestion("public.example.ir.", D.TypeA)
			good := publicFilterTestClient{ip: "203.0.113.2", delay: 10 * time.Millisecond}
			msg, _, err := batchExchange(context.Background(), []dnsClient{publicIPClient{tc.bad}, publicIPClient{good}}, q)
			if err != nil {
				t.Fatal(err)
			}
			if len(msg.Answer) != 1 || msg.Answer[0].(*D.A).A.String() != good.ip {
				t.Fatalf("unusable response won: %v", msg)
			}
		})
	}
}

func TestPublicIPPoolPreservesNegativeAfterAllServers(t *testing.T) {
	for _, rcode := range []int{D.RcodeNameError, D.RcodeSuccess} {
		q := new(D.Msg)
		q.SetQuestion("missing.example.ir.", D.TypeA)
		msg, cache, err := batchExchange(context.Background(), []dnsClient{
			publicIPClient{publicFilterTestClient{rcode: rcode}},
			publicIPClient{publicFilterTestClient{rcode: rcode, delay: time.Millisecond}},
		}, q)
		if err != nil || !cache || msg == nil || msg.Rcode != rcode || len(msg.Answer) != 0 {
			t.Fatalf("negative semantics changed: msg=%v cache=%v err=%v", msg, cache, err)
		}
	}
}

func TestPublicIPPoolNeverReturnsOnlyPoisonedAnswers(t *testing.T) {
	q := new(D.Msg)
	q.SetQuestion("public.example.ir.", D.TypeA)
	msg, _, err := batchExchange(context.Background(), []dnsClient{
		publicIPClient{publicFilterTestClient{ip: "198.18.1.2", cname: true}},
		publicIPClient{publicFilterTestClient{ip: "10.0.0.1"}},
	}, q)
	if err == nil || msg != nil {
		t.Fatalf("poisoned answer accepted: msg=%v err=%v", msg, err)
	}
}

func TestPublicIPFilterIsOptInAndDoesNotAffectOtherTypes(t *testing.T) {
	q := new(D.Msg)
	q.SetQuestion("printer.lan.", D.TypeA)
	client := publicFilterTestClient{ip: "192.168.1.20"}
	for _, params := range []map[string]string{nil, {"dm-public-ip": "false"}} {
		msg, _, err := batchExchange(context.Background(), []dnsClient{wrapClientWithPublicIPFilter(client, params)}, q)
		if err != nil || msg.Answer[0].(*D.A).A.String() != client.ip {
			t.Fatalf("LAN/custom DNS changed: msg=%v err=%v", msg, err)
		}
	}
	for _, typ := range []uint16{D.TypeHTTPS, D.TypeSVCB, D.TypeTXT, D.TypeCNAME} {
		q.SetQuestion("public.example.ir.", typ)
		msg, err := (publicIPClient{publicFilterTestClient{}}).ExchangeContext(context.Background(), q)
		if err != nil || msg == nil {
			t.Fatalf("non-address type %d was deferred: %v", typ, err)
		}
	}
}

func TestPublicIPFilterIPv6AndMappedIPv4(t *testing.T) {
	q := new(D.Msg)
	q.SetQuestion("public.example.ir.", D.TypeAAAA)
	for _, ip := range []string{"::1", "fd00::1", "fe80::1", "::ffff:10.0.0.1", "::ffff:198.18.1.2"} {
		if _, err := (publicIPClient{publicFilterTestClient{ip: ip}}).ExchangeContext(context.Background(), q); err == nil {
			t.Fatalf("accepted non-public IPv6 %s", ip)
		}
	}
	if _, err := (publicIPClient{publicFilterTestClient{ip: "2001:db8::1"}}).ExchangeContext(context.Background(), q); err != nil {
		t.Fatal(err)
	}
}

func TestPublicIPFilterWiringPreservesUnfilteredLAN(t *testing.T) {
	plain := NameServer{Addr: "192.0.2.1:53"}
	filtered := NameServer{Addr: "192.0.2.1:53", Params: map[string]string{"dm-public-ip": "true"}}
	r := NewResolver(Config{
		Main: []NameServer{plain}, DirectServer: []NameServer{plain},
		Policy: []Policy{{Domain: "+.ir", NameServers: []NameServer{filtered}}}, DirectFollowPolicy: true,
	})
	q := new(D.Msg)
	q.SetQuestion("public.example.ir.", D.TypeA)
	for _, resolver := range []*Resolver{r.Resolver, r.DirectResolver} {
		matched := resolver.matchPolicy(q)
		if len(matched) != 1 {
			t.Fatal("domestic policy missing")
		}
		if _, ok := matched[0].(publicIPClient); !ok {
			t.Fatal("policy did not install response validation")
		}
		if _, ok := resolver.main[0].(publicIPClient); ok {
			t.Fatal("public filter leaked into general/LAN resolver")
		}
	}
}
