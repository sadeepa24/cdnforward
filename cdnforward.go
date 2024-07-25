// Package forward implements a forwarding proxy. It caches an upstream net.Conn for some time, so if the same
// client returns the upstream's Conn will be precached. Depending on how you benchmark this looks to be
// 50% faster than just opening a new connection for every client. It works with UDP and TCP and uses
// inband healthchecking.
package cdnforward

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
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
)

var log = clog.NewWithPlugin("cdn")

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
	
	Jsondata Data
	DNSupdater *Updatedns
	logfile *fileOBJ


}


type fileOBJ struct {
	writer io.Writer
}

//writing logs to txt file(extranal thread)

// New returns a new Forward.
func New() *Forward {
	f := &Forward{maxfails: 2, tlsConfig: new(tls.Config), expire: defaultExpire, p: new(random), from: ".", hcInterval: hcInterval, opts: proxy.Options{ForceTCP: false, PreferUDP: false, HCRecursionDesired: true, HCDomain: "."}}
	f.Jsondata = Data{}
	f.Jsondata.Loadjson("config.json")
	f.DNSupdater = &Updatedns{
		interval: f.Jsondata.Interval,
		data: &f.Jsondata,
		
	}
	f.DNSupdater.startupdater()
	file, err := os.OpenFile(f.Jsondata.Logfilename, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("can't open log file lod wo'nt work")
	}
	f.logfile = &fileOBJ{
		writer: file,
	}
	time.Sleep(5 * time.Second)
	fmt.Println(f.DNSupdater)

	return f
}
type Data struct {
	Dns_server string `json:"dns_server"`
	Dns_server_port string `json:"dns_server_port"`
	Interval time.Duration `json:"interval"`
	Logfilename string `json:"logfilename"`
	Overider []Overiderraw`json:"overider"`
}

type Overiderraw struct {
	Overide_domain string `json:"overide_domain"`
    Ip_ranges []string `json:"ip_ranges"`
	Overidehttps bool `json:"overidehttps"`
}

type Updatedns struct {
	Answer []dns.RR
	interval time.Duration
	data *Data
	Overide []overiitem
	
}
type overiitem struct {
	Overide_domain string 
	Ip_ranges []string 
	ipv4 []string
	ipv6 []string
	overidehttps bool

}
type Ipavbl struct {
	isavbl bool
}
type placeholder struct {
	hold bool
	donecount int
}

func (s *Data)Loadjson(loca string) {
	file, _ := os.ReadFile(loca)

	err := json.Unmarshal(file, s)
	if err != nil {
		panic(err)
	}

}
func logwriter(ss io.Writer, contet []dns.RR) {
	for _, v := range contet {
		_, err := ss.Write([]byte(v.String() + "\n"))
		if err != nil {
			fmt.Println(err)
		}
	}
}

func updatingadr(update *Updatedns, overideinfo Overiderraw, dnsserver string) {
	newoveriitem := overiitem{
		Overide_domain: overideinfo.Overide_domain,
		Ip_ranges: overideinfo.Ip_ranges,
		overidehttps: overideinfo.Overidehttps,
	}
	client := dns.Client{}
	r := dns.Msg{}
	r.SetQuestion(dns.Fqdn(overideinfo.Overide_domain), dns.TypeA)
	m := dns.Msg{}
	m.SetQuestion(dns.Fqdn(overideinfo.Overide_domain), dns.TypeAAAA)
	replyIPv4, _, err := client.Exchange(&r, dnsserver)
	for _, val := range replyIPv4.Answer {
		if a, ok := val.(*dns.A); ok {

			newoveriitem.ipv4 = append(newoveriitem.ipv4, a.A.String())
		}

	}
	fmt.Println(err)
	replyIPv6, _, err := client.Exchange(&m, dnsserver)
	for _, val := range replyIPv6.Answer {
		if a, ok := val.(*dns.AAAA); ok {
			newoveriitem.ipv6 = append(newoveriitem.ipv6, a.AAAA.String())
		}

	}
	fmt.Println(err)

	update.Overide = append(update.Overide, newoveriitem)


}

//Updating main domain dns record according to given duration
func updating(info *Updatedns, data *Data) {
	fmt.Println("updater started")
	for {
		for _, in := range data.Overider {
			go updatingadr(info, in, data.Dns_server+":"+ data.Dns_server_port)
		}
		time.Sleep(info.interval * time.Minute)
	}

}
// startin updaters
func (s *Updatedns) startupdater() {
	go updating(s, s.data)
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
func (f *Forward) Name() string { return "cdn" }

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
		fmt.Println("Forwarding --------------------------------------------")
	
		placeholds := placeholder{
			hold: true,
			donecount: 0,
			
		}

		for _, index := range f.DNSupdater.Overide {
			go CheckIptooveride(index, &placeholds, ret.Answer, ret)
		}

		for placeholds.hold && placeholds.donecount < len(f.Jsondata.Overider){
			fmt.Println("holding")
		}
		newans := ret.Answer
		w.WriteMsg(ret)
		go logwriter(f.logfile.writer, newans)
		return 0, nil
	}

	if upstreamErr != nil {
		return dns.RcodeServerFailure, upstreamErr
	}

	return dns.RcodeServerFailure, ErrNoHealthy
}


func CheckIptooveride(Overide overiitem, placeholder *placeholder, answeres []dns.RR, dnsMSg *dns.Msg) {
	boolvl := ipselector(answeres, Overide.Ip_ranges)

	if boolvl {
		addrtable := Overide.ipv4
		addrtableAAA := Overide.ipv6

		ii := 0
		iia := 0

		replicate := dnsMSg.Answer
		replicateplus := 0

		for innn, answer := range dnsMSg.Answer {
			if a, ok := answer.(*dns.A); ok {
				if ii > len(addrtable)-1{
					replicate = append(replicate[:innn-replicateplus], replicate[innn+1-replicateplus:]...)
					replicateplus++
				} else {
					a.A = net.ParseIP(addrtable[ii]).To4()
					s, _ :=  replicate[innn-replicateplus].(*dns.A)
					s.A = net.ParseIP(addrtable[ii]).To4()
				}
				ii = ii + 1

			}
			if aaa, okk := answer.(*dns.AAAA); okk {
				if iia > len(addrtableAAA)-1{
					replicate = append(replicate[:innn-replicateplus], replicate[innn+1-replicateplus:]...)
					replicateplus++
				} else {
					aaa.AAAA = net.ParseIP(addrtableAAA[iia]).To16()
					l, _ :=  replicate[innn-replicateplus].(*dns.AAAA)
					l.AAAA = net.ParseIP(addrtableAAA[iia]).To16()
				}
				
				iia = iia + 1

			}
			
			// if https, yes := answer.(*dns.HTTPS); yes || Overide.overidehttps {
			// 	fmt.Println(https)
			// 	fmt.Println(https.SVCB.Value)
			// }
			// fmt.Println(answer.(*dns.HTTPS))
		}

		dnsMSg.Answer = replicate
		placeholder.donecount++
		placeholder.hold = false
	
	} else {
		placeholder.donecount++
	}

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






func ipselector(answ []dns.RR, iprange []string) bool {
	ip := "ss"
	for mmm := range answ {
		ip = strings.Split(answ[mmm].String(), "\t")[4]
		ipAddri := net.ParseIP(ip)
		if ipAddri != nil {
			sss, _ := ipINCIDRlist(ip, iprange)
			return sss
		}
	}
	ss, _ := ipINCIDRlist(ip, iprange)
	return ss
}


func ipInCIDRs(ip, cidr string, ch *Ipavbl, wg *sync.WaitGroup) {
    ipAddr := net.ParseIP(ip)
    _, ipNet, _ := net.ParseCIDR(cidr)
	if ipNet.Contains(ipAddr) {
		ch.isavbl = true
	}
	wg.Done()
}


func ipINCIDRlist(ip string, cidr []string) (bool, error) {
	ipAddr := net.ParseIP(ip)

	if ipAddr == nil {
		return false, nil
	}
	check := Ipavbl{
		isavbl: false,
	}
	wg := &sync.WaitGroup{}
	for _, v := range cidr {
		wg.Add(1)
		go ipInCIDRs(ip, v, &check, wg)
	}
	wg.Wait()
	return check.isavbl, nil
}
