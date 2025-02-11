// Package forward implements a forwarding proxy. It caches an upstream net.Conn for some time, so if the same
// client returns the upstream's Conn will be precached. Depending on how you benchmark this looks to be
// 50% faster than just opening a new connection for every client. It works with UDP and TCP and uses
// inband healthchecking.
package forward

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync/atomic"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/debug"
	"github.com/coredns/coredns/plugin/dnstap"
	"github.com/coredns/coredns/plugin/metadata"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/plugin/pkg/proxy"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
	ot "github.com/opentracing/opentracing-go"
	otext "github.com/opentracing/opentracing-go/ext"

	"github.com/yl2chen/cidranger"
)

var log = clog.NewWithPlugin("cdnforward")

const (
	defaultExpire = 10 * time.Second
	hcInterval    = 500 * time.Millisecond
)

// Forward represents a plugin instance that can proxy requests to another (DNS) server. It has a list
// of proxies each representing one upstream proxy.
type Forward struct {
	concurrent int64 // atomic counters need to be first in struct for proper alignment

	proxies    []*proxy.Proxy
	p          Policy
	hcInterval time.Duration

	from    string
	ignored []string

	nextAlternateRcodes []int

	tlsConfig     *tls.Config
	tlsServerName string
	maxfails      uint32
	expire        time.Duration
	maxConcurrent int64

	opts proxy.Options // also here for testing

	// ErrLimitExceeded indicates that a query was rejected because the number of concurrent queries has exceeded
	// the maximum allowed (maxConcurrent)
	ErrLimitExceeded error

	tapPlugins []*dnstap.Dnstap // when dnstap plugins are loaded, we use to this to send messages out.

	Next plugin.Handler

	ipnets []ipunit

}

type ipunit struct {
	cidranger.Ranger
	addr net.IP
	forceclean bool
	preAnswereIPV4 []dns.RR
	preAnswereIPV6 []dns.RR
}

type overiderconfig struct {
	answeres []string
	cidrRng []string
	forceclean bool
}

func (i ipunit) forceChaqngeSelect(ipv4, ipv6 bool, name string) []dns.RR {
	pre := []dns.RR{}
	if ipv4 {
		for _, k := range i.preAnswereIPV4 {
			k.Header().Name = name
			pre = append(pre, k)
		}
		
	}
	if ipv6 {
		for _, k := range i.preAnswereIPV4 {
			k.Header().Name = name
			pre = append(pre, k)
		}
	}
	
	return pre

}
func (f *Forward) RegisterOveriders(overides []overiderconfig)  error {
	if len(overides) == 0 {
		return nil
	}

	for _, r := range overides {
		if len(r.answeres) ==0 || len(r.cidrRng) == 0 {
			return errors.New("pre answere and cidr range length cannot be zero")
		}
		ranger := cidranger.NewPCTrieRanger()
		for _, cidr := range r.cidrRng {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				log.Fatal(err)
			}
			err = ranger.Insert(cidranger.NewBasicRangerEntry(*ipNet))
			if err != nil {
				log.Fatal(err)
			}
			//allipnets = append(allipnets, ipNet)
		}
	
		var (
			ipv4, ipv6 []dns.RR
		)
		for _, l := range r.answeres {
			ip := net.ParseIP(l)
			if ip.To4() == nil {
				ipv6 = append(ipv6, &dns.AAAA{
					Hdr: dns.RR_Header{
						Rrtype: dns.TypeAAAA,
						Rdlength: 16,
						Ttl: 300,
						Class: dns.ClassINET,
					},
					AAAA: ip,
				})
			} else {
				ipv4 = append(ipv4, &dns.A{
					Hdr: dns.RR_Header{
						Rrtype: dns.TypeA,
						Rdlength: 4,
						Ttl: 300,
						Class: dns.ClassINET,
					},
					A: ip.To4(),
				})
			}
			
			
		}
	
		ii := ipunit{
			Ranger: ranger,
			addr: net.ParseIP(r.answeres[0]),
			forceclean: r.forceclean,
			preAnswereIPV4: ipv4,
			preAnswereIPV6: ipv6,
		}
		f.ipnets = append(f.ipnets,  ii)
	}

	return nil
}


// New returns a new Forward.
func New() *Forward {
	f := &Forward{maxfails: 2, tlsConfig: new(tls.Config), expire: defaultExpire, p: new(random), from: ".", hcInterval: hcInterval, opts: proxy.Options{ForceTCP: false, PreferUDP: false, HCRecursionDesired: true, HCDomain: "."}}
	return f
}

// SetProxy appends p to the proxy list and starts healthchecking.
func (f *Forward) SetProxy(p *proxy.Proxy) {
	f.proxies = append(f.proxies, p)
	p.Start(f.hcInterval)
}

// SetTapPlugin appends one or more dnstap plugins to the tap plugin list.
func (f *Forward) SetTapPlugin(tapPlugin *dnstap.Dnstap) {
	f.tapPlugins = append(f.tapPlugins, tapPlugin)
	if nextPlugin, ok := tapPlugin.Next.(*dnstap.Dnstap); ok {
		f.SetTapPlugin(nextPlugin)
	}
}

// Len returns the number of configured proxies.
func (f *Forward) Len() int { return len(f.proxies) }

// Name implements plugin.Handler.
func (f *Forward) Name() string { return "cdnforward" }

// ServeDNS implements plugin.Handler.
func (f *Forward) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}
	if !f.match(state) {
		return plugin.NextOrFailure(f.Name(), f.Next, ctx, w, r)
	}

	if f.maxConcurrent > 0 {
		count := atomic.AddInt64(&(f.concurrent), 1)
		defer atomic.AddInt64(&(f.concurrent), -1)
		if count > f.maxConcurrent {
			maxConcurrentRejectCount.Add(1)
			return dns.RcodeRefused, f.ErrLimitExceeded
		}
	}

	fails := 0
	var span, child ot.Span
	var upstreamErr error
	span = ot.SpanFromContext(ctx)
	i := 0
	list := f.List()
	deadline := time.Now().Add(defaultTimeout)
	start := time.Now()
	for time.Now().Before(deadline) && ctx.Err() == nil {
		if i >= len(list) {
			// reached the end of list, reset to begin
			i = 0
			fails = 0
		}

		proxy := list[i]
		i++
		if proxy.Down(f.maxfails) {
			fails++
			if fails < len(f.proxies) {
				continue
			}
			// All upstream proxies are dead, assume healthcheck is completely broken and randomly
			// select an upstream to connect to.
			r := new(random)
			proxy = r.List(f.proxies)[0]

			healthcheckBrokenCount.Add(1)
		}

		if span != nil {
			child = span.Tracer().StartSpan("connect", ot.ChildOf(span.Context()))
			otext.PeerAddress.Set(child, proxy.Addr())
			ctx = ot.ContextWithSpan(ctx, child)
		}

		metadata.SetValueFunc(ctx, "forward/upstream", func() string {
			return proxy.Addr()
		})

		var (
			ret *dns.Msg
			err error
		)
		opts := f.opts

		for {
			ret, err = proxy.Connect(ctx, state, opts)

			if err == ErrCachedClosed { // Remote side closed conn, can only happen with TCP.
				continue
			}
			// Retry with TCP if truncated and prefer_udp configured.
			if ret != nil && ret.Truncated && !opts.ForceTCP && opts.PreferUDP {
				opts.ForceTCP = true
				continue
			}
			break
		}

		if child != nil {
			child.Finish()
		}

		if len(f.tapPlugins) != 0 {
			toDnstap(ctx, f, proxy.Addr(), state, opts, ret, start)
		}

		upstreamErr = err

		if err != nil {
			// Kick off health check to see if *our* upstream is broken.
			if f.maxfails != 0 {
				proxy.Healthcheck()
			}

			if fails < len(f.proxies) {
				continue
			}
			break
		}

		// Check if the reply is correct; if not return FormErr.
		if !state.Match(ret) {
			debug.Hexdumpf(ret, "Wrong reply for id: %d, %s %d", ret.Id, state.QName(), state.QType())

			formerr := new(dns.Msg)
			formerr.SetRcode(state.Req, dns.RcodeFormatError)
			w.WriteMsg(formerr)
			return 0, nil
		}

		// Check if we have an alternate Rcode defined, check if we match on the code
		for _, alternateRcode := range f.nextAlternateRcodes {
			if alternateRcode == ret.Rcode && f.Next != nil { // In case we do not have a Next handler, just continue normally
				if _, ok := f.Next.(*Forward); ok { // Only continue if the next forwarder is also a Forworder
					return plugin.NextOrFailure(f.Name(), f.Next, ctx, w, r)
				}
			}
		}

		//var changeallRecord bool
		var (
			fakeloop bool
			foundipv6 bool
			foundipv4 bool
			ipunit ipunit
			name string
		)
		answere:
		for i, answere := range ret.Answer {
			switch dnsAns := answere.(type) {
			case *dns.AAAA:
				foundipv6 = true
				if fakeloop {
					continue answere
			    }
				for j, r := range f.ipnets {
				   cont,err := f.ipnets[j].Ranger.Contains(dnsAns.AAAA)
				   if err != nil {
					   continue
				   }
				   if r.forceclean {
						fakeloop = true
						ipunit = f.ipnets[j]
						name = dnsAns.Hdr.Name
					}
				   if cont {
					   ret.Answer[i] = &dns.AAAA{Hdr: dnsAns.Hdr, AAAA: r.addr}
				   }
			   }
			case *dns.A:
				foundipv4 = true
				if fakeloop {
					continue
				}
				for j, r := range f.ipnets {
					cont,err := f.ipnets[j].Ranger.Contains(dnsAns.A)
					if err != nil {
						continue
					}
					if r.forceclean {
						fakeloop = true
						ipunit = f.ipnets[j]
						name = dnsAns.Hdr.Name
					}
					if cont {
						ret.Answer[i] = &dns.A{Hdr: dnsAns.Hdr, A: r.addr}
					}
				}
			}
		}
		if fakeloop {
			ret.Answer = ipunit.forceChaqngeSelect(foundipv4, foundipv6, name)
		}
		w.WriteMsg(ret)
		return 0, nil
	}

	if upstreamErr != nil {
		return dns.RcodeServerFailure, upstreamErr
	}

	return dns.RcodeServerFailure, ErrNoHealthy
}

func (f *Forward) match(state request.Request) bool {
	if !plugin.Name(f.from).Matches(state.Name()) || !f.isAllowedDomain(state.Name()) {
		return false
	}
	return true
}

func (f *Forward) isAllowedDomain(name string) bool {
	if dns.Name(name) == dns.Name(f.from) {
		return true
	}
	for _, ignore := range f.ignored {
		if plugin.Name(ignore).Matches(name) {
			return false
		}
	}
	return true
}

// ForceTCP returns if TCP is forced to be used even when the request comes in over UDP.
func (f *Forward) ForceTCP() bool { return f.opts.ForceTCP }

// PreferUDP returns if UDP is preferred to be used even when the request comes in over TCP.
func (f *Forward) PreferUDP() bool { return f.opts.PreferUDP }

// List returns a set of proxies to be used for this client depending on the policy in f.
func (f *Forward) List() []*proxy.Proxy { return f.p.List(f.proxies) }

var (
	// ErrNoHealthy means no healthy proxies left.
	ErrNoHealthy = errors.New("no healthy proxies")
	// ErrNoForward means no forwarder defined.
	ErrNoForward = errors.New("no forwarder defined")
	// ErrCachedClosed means cached connection was closed by peer.
	ErrCachedClosed = errors.New("cached connection was closed by peer")
)

// Options holds various Options that can be set.
type Options struct {
	// ForceTCP use TCP protocol for upstream DNS request. Has precedence over PreferUDP flag
	ForceTCP bool
	// PreferUDP use UDP protocol for upstream DNS request.
	PreferUDP bool
	// HCRecursionDesired sets recursion desired flag for Proxy healthcheck requests
	HCRecursionDesired bool
	// HCDomain sets domain for Proxy healthcheck requests
	HCDomain string
}

var defaultTimeout = 5 * time.Second
