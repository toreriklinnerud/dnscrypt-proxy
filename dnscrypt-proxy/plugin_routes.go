package main

import (
	"net"
	"strings"
	"fmt"
	"math/rand"
	"regexp"
	"github.com/BurntSushi/toml"
	"github.com/vishvananda/netlink"
	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
)

type Peer struct {
	Name string
	Dns []string
	Link string
	Endpoint net.IP
	Domains []string
}

type Peers struct {
	Peer []Peer
}

type PeerRoute struct {
	peer *Peer
	dns_servers *[]string
	domain regexp.Regexp
}

type PluginRoutes struct {
	peer_routes []PeerRoute
}

func (plugin *PluginRoutes) Name() string {
	return "routes"
}

func (plugin *PluginRoutes) Description() string {
	return "Just-in-time routing of IP addresses matching DNS lookups. DNS wildcards allowed."
}

func (plugin *PluginRoutes) Init(proxy *Proxy) error {
	var peers Peers
	if _, err := toml.DecodeFile(proxy.routePeersFile, &peers); err != nil {
		dlog.Fatal(err)
	}

	plugin.peer_routes = []PeerRoute{}
	for _, peer := range peers.Peer {

		var dns_servers []string
		for _, dns_server := range peer.Dns {
			if net.ParseIP(dns_server) != nil {
				dns_server = fmt.Sprintf("%s:%d", dns_server, 53)
			}
			dns_servers = append(dns_servers, dns_server)
		}

		for _, domain := range peer.Domains {
			pattern := ".*" + strings.ReplaceAll(regexp.QuoteMeta(domain), "\\*", ".+")
			compiled, _ := regexp.Compile(pattern)
			plugin.peer_routes = append(plugin.peer_routes, PeerRoute{peer: &peer, dns_servers: &dns_servers, domain: *compiled})
		}
	}

	dlog.Notice("Routes loaded:")
	for _, peer_route := range plugin.peer_routes {
		dlog.Noticef("%s %s", peer_route.peer.Name, peer_route.domain.String())
	}

	return nil
}

func (plugin *PluginRoutes) Drop() error {
	return nil
}

func (plugin *PluginRoutes) Reload() error {
	return nil
}

func (plugin *PluginRoutes) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	question := msg.Question[0]
	dlog.Noticef("Domain %s", question.Name)
	if question.Qclass != dns.ClassINET || (question.Qtype != dns.TypeA) {
		return nil
	}
	var peer *Peer = nil
	var dns_servers []string = nil
	for _, route := range plugin.peer_routes {
			if route.domain.MatchString(question.Name)  {
					peer = route.peer
					dns_servers = *route.dns_servers
					break
			}
	}

	if peer == nil {
		return nil
	}

	link, _ := netlink.LinkByName(peer.Link)
	server := dns_servers[rand.Intn(len(dns_servers))]

	client := dns.Client{Net: pluginsState.serverProto, Timeout: pluginsState.timeout}
	respMsg, _, err := client.Exchange(msg, server)
	if err != nil {
			dlog.Warnf("-- err: %s", err)

		return err
	}

	if respMsg.Truncated {
		client.Net = "tcp"
		respMsg, _, err = client.Exchange(msg, server)
		if err != nil {
			dlog.Warnf("-- err: %s", err)
			return err
		}
	}

	if edns0 := respMsg.IsEdns0(); edns0 == nil || !edns0.Do() {
		respMsg.AuthenticatedData = false
	}

	answers := respMsg.Answer

	if len(answers) == 0 {
		return nil
	}

	for _, answer := range answers {
		header := answer.Header()
		Rrtype := header.Rrtype
		if header.Class != dns.ClassINET || (Rrtype != dns.TypeA) {
			continue
		}
		if Rrtype == dns.TypeA {
			destination_ip := net.ParseIP(answer.(*dns.A).A.String())
			destination := &net.IPNet{destination_ip, net.CIDRMask(32, 32)}

			route := netlink.Route{
				Scope:     netlink.SCOPE_UNIVERSE,
				LinkIndex: link.Attrs().Index,
				Dst: destination,
				Gw: peer.Endpoint,
			}
			error := netlink.RouteReplace(&route)
			if(error == nil) {
				dlog.Noticef("-- routing %s via %s", destination, peer.Name)
			} else {
				dlog.Errorf("-- error adding route: %s", error)
			}
		}
	}

	respMsg.Id = msg.Id
	pluginsState.synthResponse = respMsg
	pluginsState.action = PluginsActionSynth
	pluginsState.returnCode = PluginsReturnCodeForward

	return nil
}
