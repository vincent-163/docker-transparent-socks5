package proxy

import (
	"net"
	"sync"

	"github.com/LiamHaworth/go-tproxy"
)

type UDPProxy interface {
	DialUDP(string, *net.UDPAddr, *net.UDPAddr) (net.PacketConn, error)
}

type UDPTProxy struct {
	UpstreamProxy UDPProxy
	LocalAddr     string

	udpConn    *net.UDPConn
	mu         sync.Mutex
	conns      map[string]*udpConnection
	packetPool sync.Pool
}

type udpConnection struct {
	packets chan *packet
}

type packet struct {
	b          []byte
	remoteAddr *net.UDPAddr
}

func (p *UDPTProxy) Serve() error {
	p.packetPool.New = func() interface{} {
		return &packet{
			b: make([]byte, 0, 4096),
		}
	}
	udpAddr, err := net.ResolveUDPAddr("udp", p.LocalAddr)
	if err != nil {
		return err
	}
	udpConn, err := tproxy.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	defer func() {
		go udpConn.Close()
	}()
	p.udpConn = udpConn
	p.conns = make(map[string]*udpConnection)
	defer func() {
		p.mu.Lock()
		for _, conn := range p.conns {
			close(conn.packets)
		}
		p.mu.Unlock()
	}()

	var err2 error
	for {
		pk := p.packetPool.Get().(*packet)
		n, local, remote, err := tproxy.ReadFromUDP(udpConn, pk.b[0:4096:4096])
		if err != nil {
			err2 = err
			break
		}
		pk.b = pk.b[0:n:4096]
		pk.remoteAddr = remote
		log.Infof("Serving UDP packet %s -> %s", local, remote)
		s := local.String() // TODO: this is inefficient, use another map key

		p.mu.Lock()
		conn, ok := p.conns[s]
		if !ok {
			conn = &udpConnection{}
			conn.packets = make(chan *packet, 100)
			p.conns[s] = conn
			go p.handleConn(conn, local, remote)
		}
		select {
		case conn.packets <- pk:
		default:
		}
		p.mu.Unlock()
	}
	return err2
}

func (p *UDPTProxy) handleConn(conn *udpConnection, local *net.UDPAddr, remote *net.UDPAddr) {
	// TODO: remove connection from p.conns when connection closes
	udpConn, err := p.UpstreamProxy.DialUDP("udp", nil, remote)
	if err != nil {
		log.WithError(err).Error("failed to dial upstream udp")
		return
	}
	go func() {
		buf := make([]byte, 4096)
		for {
			b, addr, err := udpConn.ReadFrom(buf)
			if err != nil {
				log.WithError(err).Error("failed to read from udp socket")
				break
			}
			log.Infof("Received packet %s -> %s", addr, local)
			_, err = WriteToUDP(p.udpConn, addr.(*net.UDPAddr), local, buf[:b])
			if err != nil {
				log.WithError(err).Error("failed to send udp packet")
				break
			}
		}
	}()
	for packet := range conn.packets {
		log.Infof("packet len %d to %s", len(packet.b), packet.remoteAddr)
		_, err := udpConn.WriteTo(packet.b, packet.remoteAddr)
		if err != nil {
			log.WithError(err).Warning("failed to forward udp packet")
		}
	}
}

func (p *UDPTProxy) Close() error {
	go p.udpConn.Close()
	return nil
}
