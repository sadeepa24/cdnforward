package forward

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/coredns/caddy"
	"github.com/coredns/caddy/caddyfile"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin/dnstap"
	"github.com/coredns/coredns/plugin/pkg/proxy"
	"github.com/coredns/coredns/plugin/pkg/transport"
	"github.com/miekg/dns"
)

func TestList(t *testing.T) {
	f := Forward{
		proxies: []*proxy.Proxy{
			proxy.NewProxy("TestList", "1.1.1.1:53", transport.DNS),
			proxy.NewProxy("TestList", "2.2.2.2:53", transport.DNS),
			proxy.NewProxy("TestList", "3.3.3.3:53", transport.DNS),
		},
		p: &roundRobin{},
	}

	expect := []*proxy.Proxy{
		proxy.NewProxy("TestList", "2.2.2.2:53", transport.DNS),
		proxy.NewProxy("TestList", "1.1.1.1:53", transport.DNS),
		proxy.NewProxy("TestList", "3.3.3.3:53", transport.DNS),
	}
	got := f.List()

	if len(got) != len(expect) {
		t.Fatalf("Expected: %v results, got: %v", len(expect), len(got))
	}
	for i, p := range got {
		if p.Addr() != expect[i].Addr() {
			t.Fatalf("Expected proxy %v to be '%v', got: '%v'", i, expect[i].Addr(), p.Addr())
		}
	}
}

func TestSetTapPlugin(t *testing.T) {
	input := `forward . 127.0.0.1
	dnstap /tmp/dnstap.sock full
	dnstap tcp://example.com:6000
	`
	stanzas := strings.Split(input, "\n")
	c := caddy.NewTestController("dns", strings.Join(stanzas[1:], "\n"))
	dnstapSetup, err := caddy.DirectiveAction("dns", "dnstap")
	if err != nil {
		t.Fatal(err)
	}
	if err = dnstapSetup(c); err != nil {
		t.Fatal(err)
	}
	c.Dispenser = caddyfile.NewDispenser("", strings.NewReader(stanzas[0]))
	if err = setup(c); err != nil {
		t.Fatal(err)
	}
	dnsserver.NewServer("", []*dnsserver.Config{dnsserver.GetConfig(c)})
	f, ok := dnsserver.GetConfig(c).Handler("forward").(*Forward)
	if !ok {
		t.Fatal("Expected a forward plugin")
	}
	tap, ok := dnsserver.GetConfig(c).Handler("dnstap").(*dnstap.Dnstap)
	if !ok {
		t.Fatal("Expected a dnstap plugin")
	}
	f.SetTapPlugin(tap)
	if len(f.tapPlugins) != 2 {
		t.Fatalf("Expected: 2 results, got: %v", len(f.tapPlugins))
	}
	if f.tapPlugins[0] != tap || tap.Next != f.tapPlugins[1] {
		t.Error("Unexpected order of dnstap plugins")
	}
}

func TestSendDNSQuestion(t *testing.T) {
	// Create a DNS question
	question := new(dns.Msg)
	question.SetQuestion("example.com.", dns.TypeA)

	// Send the DNS question to 127.0.0.1:53
	client := new(dns.Client)
	response, _, err := client.Exchange(question, " 192.168.194.5:53")
	if err != nil {
		t.Fatalf("Failed to send DNS question: %v", err)
	}

	// Check the response
	if response == nil {
		t.Fatal("Expected a response, got nil")
	}
	if response.Rcode != dns.RcodeSuccess {
		t.Fatalf("Expected RcodeSuccess, got: %v", response.Rcode)
	}

}
func TestForwardInterface(t *testing.T) {
	// f := Forward{
	// 	proxies: []*proxy.Proxy{
	// 		proxy.NewProxy("TestForwardInterface", "8.8.8.8:53", transport.DNS),
	// 	},
	// 	p: &roundRobin{},
	// 	Next: &dummyNextHandler{},


	// }

	f  := New()
	pt := proxy.NewProxy("TestForwardInterface", "1.1.1.1:53", transport.DNS)
	f.proxies = append(f.proxies, pt)
	f.Next = &dummyNextHandler{}
	f.p = &roundRobin{}

	gg := overiderconfig{
		answeres: []string{"104.27.206.92", "1.1.1.1"},
		cidrRng: []string{"0.0.0.0/0"},
		forceclean: true,
	}
	f.RegisterOveriders(gg)



	// Test Name method
	if f.Name() != "cdnforward" {
		t.Fatalf("Expected Name to be 'cdnforward', got: '%v'", f.Name())
	}

	// Test ServeDNS method
	question := new(dns.Msg)
	question.SetQuestion("example.com", dns.TypeA)
	//rec := &dnsserver.
	rec := &dummyResponseWriter{}
	_, err := f.ServeDNS(context.Background(), rec, question)
	if err != nil {
		t.Fatalf("ServeDNS returned an error: %v", err)
	}

	// Test OnStartup method
	err = f.OnStartup()
	if err != nil {
		t.Fatalf("OnStartup returned an error: %v", err)
	}

	// Test OnShutdown method
	err = f.OnShutdown()
	if err != nil {
		t.Fatalf("OnShutdown returned an error: %v", err)
	}
}


type dummyResponseWriter struct{}

func (d *dummyResponseWriter) LocalAddr() (la net.Addr) {
	fmt.Println("LocalAddr called")
	return
}

func (d *dummyResponseWriter) RemoteAddr() (ra net.Addr) {
	fmt.Println("RemoteAddr called")
	//ra = &net.ParseIP("127.0.0.1")
	return 
}

func (d *dummyResponseWriter) WriteMsg(m *dns.Msg) error {
	fmt.Println("WriteMsg called")
	fmt.Println(m.Answer)
	return nil
}

func (d *dummyResponseWriter) Write(b []byte) (int, error) {
	fmt.Println("Write called")
	return len(b), nil
}

func (d *dummyResponseWriter) Close() error {
	fmt.Println("Close called")
	return nil
}

func (d *dummyResponseWriter) TsigStatus() error {
	fmt.Println("TsigStatus called")
	return nil
}

func (d *dummyResponseWriter) TsigTimersOnly(bool) {
	fmt.Println("TsigTimersOnly called")
}

func (d *dummyResponseWriter) Hijack() {
	fmt.Println("Hijack called")
}

func (d *dummyResponseWriter) WriteMsgWithContext(ctx context.Context, m *dns.Msg) error {
	fmt.Println("WriteMsgWithContext called")
	return nil
}



type dummyNextHandler struct{}

func (d *dummyNextHandler) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	fmt.Println("dummyNextHandler ServeDNS called")
	return dns.RcodeSuccess, nil
}

func (d *dummyNextHandler) Name() string {
	return "dummyNextHandler"
}