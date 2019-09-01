package main

import (
	"fmt"
	"net"

	"github.com/vincent-163/docker-transparent-socks5/netop"
	"github.com/vincent-163/docker-transparent-socks5/proxy"
)

type network struct {
	bridgeName        string
	gatewayIPv4       net.IP
	gatewayIPv4Subnet *net.IPNet
	gatewayIPv4CIDR   string
	gatewayIPv6       net.IP
	gatewayIPv6Subnet *net.IPNet
	gatewayIPv6CIDR   string
	endpoints         map[string]*endpoint

	tcpProxy *proxy.TCPTProxy
	udpProxy *proxy.UDPTProxy

	cancel func()
}

type endpoint struct {
	veth1Name  string
	veth2Name  string
	address    string
	addressv6  string
	macAddress string
}

func (d *Driver) createNetwork(name string, ipv4data *NetworkData, ipv6data *NetworkData) (*network, error) {
	n := &network{}
	n.endpoints = make(map[string]*endpoint)
	n.bridgeName = fmt.Sprintf("br-%s", name)
	if ipv4data != nil {
		ipv4, ipv4net, err := net.ParseCIDR(ipv4data.Gateway)
		if err != nil {
			return nil, fmt.Errorf("failed to parse gateway %s: %s", ipv4data.Gateway, err)
		}
		n.gatewayIPv4 = ipv4
		n.gatewayIPv4Subnet = ipv4net
		n.gatewayIPv4CIDR = ipv4data.Gateway
	}
	if ipv6data != nil {
		ipv6, ipv6net, err := net.ParseCIDR(ipv6data.Gateway)
		if err != nil {
			return nil, fmt.Errorf("failed to parse gateway %s: %s", ipv6data.Gateway, err)
		}
		n.gatewayIPv6 = ipv6
		n.gatewayIPv6Subnet = ipv6net
		n.gatewayIPv6CIDR = ipv6data.Gateway
	}
	if n.gatewayIPv4 != nil {
		n.tcpProxy = &proxy.TCPTProxy{
			UpstreamProxy: d.tcpProxy,
			LocalAddr:     net.JoinHostPort(n.gatewayIPv4.String(), "12345"),
		}
		n.udpProxy = &proxy.UDPTProxy{
			UpstreamProxy: d.udpProxy,
			LocalAddr:     net.JoinHostPort(n.gatewayIPv4.String(), "12345"),
		}
	}
	if err := n.create(); err != nil {
		return nil, err
	}
	return n, nil
}

func (n *network) create() error {
	if err := netop.CreateBridge(n.bridgeName); err != nil {
		return err
	}
	if n.gatewayIPv4 != nil {
		if err := netop.AddAddr(n.bridgeName, n.gatewayIPv4CIDR); err != nil {
			return err
		}
	}
	if n.gatewayIPv6 != nil {
		if err := netop.AddAddrV6(n.bridgeName, n.gatewayIPv6CIDR); err != nil {
			return err
		}
	}
	if err := netop.ExecIptables("-t", "mangle", "-A", "PREROUTING", "-i", n.bridgeName, "-p", "tcp", "-j", "TPROXY", "--tproxy-mark", "0x1/0x1", "--on-ip", n.gatewayIPv4.String(), "--on-port", "12345"); err != nil {
		return err
	}
	if err := netop.ExecIptables("-t", "mangle", "-A", "PREROUTING", "-i", n.bridgeName, "-p", "udp", "-j", "TPROXY", "--tproxy-mark", "0x1/0x1", "--on-ip", n.gatewayIPv4.String(), "--on-port", "12345"); err != nil {
		return err
	}
	if err := netop.SetInterfaceUp(n.bridgeName); err != nil {
		return err
	}
	if n.tcpProxy != nil {
		go func() {
			if err := n.tcpProxy.Serve(); err != nil {
				log.WithError(err).Error("Failed to serve TCP")
			}
		}()
	}
	if n.udpProxy != nil {
		go func() {
			if err := n.udpProxy.Serve(); err != nil {
				log.WithError(err).Error("Failed to serve UDP")
			}
		}()
	}
	return nil
}

func (n *network) destroy() error {
	if err := netop.ExecIptables("-t", "mangle", "-D", "PREROUTING", "-i", n.bridgeName, "-p", "tcp", "-j", "TPROXY", "--tproxy-mark", "0x1/0x1", "--on-ip", n.gatewayIPv4.String(), "--on-port", "12345"); err != nil {
		return err
	}
	if err := netop.ExecIptables("-t", "mangle", "-D", "PREROUTING", "-i", n.bridgeName, "-p", "udp", "-j", "TPROXY", "--tproxy-mark", "0x1/0x1", "--on-ip", n.gatewayIPv4.String(), "--on-port", "12345"); err != nil {
		return err
	}
	if err := netop.DeleteInterface(n.bridgeName); err != nil {
		return err
	}
	if n.tcpProxy != nil {
		n.tcpProxy.Close()
	}
	if n.udpProxy != nil {
		n.udpProxy.Close()
	}
	return nil
}

func (n *network) createEndpoint(id string, data *EndpointInterface, options map[string]interface{}) error {
	name := newRandomHex(4)
	ep := &endpoint{}
	ep.veth1Name = fmt.Sprintf("veth%s-a", name)
	ep.veth2Name = fmt.Sprintf("veth%s-b", name)
	// TODO: support empty data
	if data == nil || data.Address == "" {
		return fmt.Errorf("auto-allocating addresses not supported yet")
	}
	ep.address = data.Address
	ep.addressv6 = data.AddressIPv6
	ep.macAddress = data.MacAddress
	if err := n.setupEndpoint(ep); err != nil {
		return fmt.Errorf("failed to create endpoint: %s", err)
	}
	n.endpoints[id] = ep
	return nil
}

func (n *network) setupEndpoint(ep *endpoint) error {
	if err := netop.CreateVeth(ep.veth1Name, ep.veth2Name); err != nil {
		return err
	}
	if err := netop.SetMaster(ep.veth1Name, n.bridgeName); err != nil {
		return err
	}
	if ep.address != "" {
		if err := netop.AddAddr(ep.veth2Name, ep.address); err != nil {
			return err
		}
	}
	if ep.addressv6 != "" {
		if err := netop.AddAddrV6(ep.veth2Name, ep.addressv6); err != nil {
			return err
		}
	}
	if err := netop.SetInterfaceUp(ep.veth1Name); err != nil {
		return err
	}
	if err := netop.SetInterfaceUp(ep.veth2Name); err != nil {
		return err
	}
	return nil
}

func (n *network) deleteEndpoint(id string) error {
	ep := n.endpoints[id]
	if err := n.unsetEndpoint(ep); err != nil {
		return err
	}
	delete(n.endpoints, id)
	return nil
}

func (n *network) unsetEndpoint(ep *endpoint) error {
	if err := netop.DeleteInterface(ep.veth1Name); err != nil {
		return err
	}
	return nil
}

func (n *network) joinEndpoint(id string, key string) (*JoinResponse, error) {
	ep := n.endpoints[id]
	resp := &JoinResponse{}
	resp.InterfaceName = &InterfaceNameInfo{
		SrcName:   ep.veth2Name,
		DstPrefix: ep.veth2Name,
	}
	if n.gatewayIPv4 != nil {
		resp.Gateway = n.gatewayIPv4.String()
	}
	if n.gatewayIPv6 != nil {
		resp.GatewayIPv6 = n.gatewayIPv6.String()
	}
	return resp, nil
}

func (n *network) leaveEndpoint(id string) error {
	return nil
}
