package main

import (
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"net"
	"regexp"
	"strings"
)

type PeerConfig struct {
	Name      string
	Link      string
	PublicKey string
	Endpoint  net.IP
	Domains   []string
}

type PeersConfig struct {
	Peer []PeerConfig
}

type Peer struct {
	Name      string
	Link      netlink.Link
	PublicKey wgtypes.Key
	Endpoint  net.IP
	Domains   []regexp.Regexp
}

type PluginRoutes struct {
	Peers []Peer
	Wg    *wgctrl.Client
}

func (plugin *PluginRoutes) Name() string {
	return "routes"
}

func (plugin *PluginRoutes) Description() string {
	return "Just-in-time routing of IP addresses matching DNS lookups. DNS wildcards allowed."
}

func (plugin *PluginRoutes) Init(proxy *Proxy) error {
	var peersConfig PeersConfig
	if _, err := toml.DecodeFile(proxy.routePeersFile, &peersConfig); err != nil {
		dlog.Fatal(err)
	}
	plugin.Wg, _ = wgctrl.New()

	plugin.Peers = []Peer{}
	for _, peerConfig := range peersConfig.Peer {

		key, _ := wgtypes.ParseKey(peerConfig.PublicKey)
		link, _ := netlink.LinkByName(peerConfig.Link)

		var domains = []regexp.Regexp{}
		for _, domain := range peerConfig.Domains {
			pattern := ".*" + strings.ReplaceAll(regexp.QuoteMeta(domain), "\\*", ".+")
			compiled, _ := regexp.Compile(pattern)
			domains = append(domains, *compiled)
		}
		plugin.Peers = append(plugin.Peers, Peer{Name: peerConfig.Name, PublicKey: key, Domains: domains, Link: link, Endpoint: peerConfig.Endpoint})
	}

	dlog.Notice("Peers loaded:")
	for _, peer := range plugin.Peers {
		dlog.Noticef("%s:", peer.Name)
		dlog.Noticef("Public Key %s", peer.PublicKey.String())
		dlog.Noticef("Link %s", peer.Link.Attrs().Name)
		dlog.Noticef("Endpoint %s", peer.Endpoint)
		dlog.Noticef("Domains:")
		for _, domain := range peer.Domains {
			dlog.Noticef(" %s", strings.Replace(domain.String(), "\\", "", -1))
		}
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

	if question.Qclass != dns.ClassINET || (question.Qtype != dns.TypeA) {
		return nil
	}
	var matchingPeer *Peer = nil
	for _, peer := range plugin.Peers {
		for _, domain := range peer.Domains {
			if domain.MatchString(question.Name) {
				matchingPeer = &peer
				break
			}
		}
	}

	if matchingPeer == nil {
		dlog.Noticef("No match for %s", question.Name)
		return nil
	}

	upstream := fmt.Sprintf("%s:%s", matchingPeer.Endpoint, "53")

	client := dns.Client{Net: pluginsState.serverProto, Timeout: pluginsState.timeout}
	respMsg, _, err := client.Exchange(msg, upstream)
	if err != nil {
		dlog.Warnf("err: %s", err)

		return err
	}

	if respMsg.Truncated {
		client.Net = "tcp"
		respMsg, _, err = client.Exchange(msg, upstream)
		if err != nil {
			dlog.Warnf("err: %s", err)
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
			plugin.AddRoute(matchingPeer, destination)
		}
	}

	respMsg.Id = msg.Id
	pluginsState.synthResponse = respMsg
	pluginsState.action = PluginsActionSynth
	pluginsState.returnCode = PluginsReturnCodeForward

	return nil
}

func (plugin *PluginRoutes) AddRoute(peer *Peer, destination *net.IPNet) {
	linkAttrs := peer.Link.Attrs()
	route := netlink.Route{
		Scope:     netlink.SCOPE_UNIVERSE,
		LinkIndex: linkAttrs.Index,
		Dst:       destination,
		Gw:        peer.Endpoint,
	}
	error := netlink.RouteReplace(&route)
	if error == nil {
		dlog.Noticef("%s routing via %s", destination.String(), peer.Name)
	} else {
		dlog.Errorf("error adding route: %s", error)
	}

	peerConfig := wgtypes.PeerConfig{
		PublicKey:         peer.PublicKey,
		ReplaceAllowedIPs: false,
		AllowedIPs:        []net.IPNet{*destination}}

	config := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peerConfig}}

	plugin.Wg.ConfigureDevice(linkAttrs.Name, config)
}
