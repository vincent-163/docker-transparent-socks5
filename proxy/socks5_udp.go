package proxy

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// SOCKS5Proxy represents a SOCKS5 Proxy. Currently only UDP is supported.
type SOCKS5Proxy struct {
	ProxyAddr *net.TCPAddr
}

func NewSOCKS5Proxy(network string, addr string) (*SOCKS5Proxy, error) {
	tcpaddr, err := net.ResolveTCPAddr(network, addr)
	if err != nil {
		return nil, err
	}
	return &SOCKS5Proxy{ProxyAddr: tcpaddr}, nil
}

// socks5udpconn implements the PacketConn interface.
type socks5udpconn struct {
	tcpConn *net.TCPConn
	udpConn *net.UDPConn
	udpAddr *net.UDPAddr
}

var ErrUnsupported = errors.New("Unsupported protocol")

// Buffer pool
var bufPool sync.Pool

func init() {
	bufPool.New = func() interface{} {
		return make([]byte, 4096)
	}
}

// Encode address in SOCKS5 format
func encodeAddr(buf *bytes.Buffer, addr *net.UDPAddr) {
	if len(addr.IP) == 4 {
		buf.WriteByte(1)
	} else if len(addr.IP) == 16 {
		buf.WriteByte(4)
	} else {
		panic("Invalid IP address")
	}
	buf.Write(addr.IP)
	buf.WriteByte(byte(addr.Port >> 16))
	buf.WriteByte(byte(addr.Port & 0xFF))
}

// Dials a given UDP address. The arguments are currently ignored.
func (p *SOCKS5Proxy) DialUDP(network string, _ *net.UDPAddr, _ *net.UDPAddr) (net.PacketConn, error) {
	conn, err := net.DialTCP("tcp", nil, p.ProxyAddr)
	if err != nil {
		return nil, err
	}
	_, err = conn.Write([]byte{5, 1, 0})
	if err != nil {
		return nil, err
	}

	buf2 := make([]byte, 4096)
	// SOCKS5 handshake reply with no auth
	_, err = io.ReadFull(conn, buf2[:2])
	if err != nil {
		return nil, err
	}
	if buf2[0] != 5 || buf2[1] != 0 {
		return nil, ErrUnsupported
	}

	// SOCKS5 UDP ASSOCIATE request
	buf := &bytes.Buffer{}
	buf.Write([]byte{5, 3, 0})
	// We haven't created the UDP socket yet so we use a zero address for the UDP ASSOCAITE request
	laddr := &net.UDPAddr{}
	laddr.IP = make([]byte, len(p.ProxyAddr.IP))
	laddr.Port = 0
	encodeAddr(buf, laddr)
	buf.WriteTo(conn)

	// SOCKS5 UDP ASSOCIATE response
	_, err = io.ReadFull(conn, buf2[:3])
	if buf2[0] != 5 || buf2[1] != 0 || buf2[2] != 0 {
		return nil, ErrUnsupported
	}
	addr := &net.UDPAddr{}
	_, err = io.ReadFull(conn, buf2[:1])
	if err != nil {
		return nil, err
	}
	switch buf2[0] {
	case 1: // IPv4
		addr.IP = make([]byte, 4)
		_, err = io.ReadFull(conn, addr.IP)
		if err != nil {
			return nil, err
		}
	case 4: // IPv6
		addr.IP = make([]byte, 16)
		_, err := io.ReadFull(conn, addr.IP)
		if err != nil {
			return nil, err
		}
	default: // 3 means domain
		return nil, ErrUnsupported
	}
	_, err = io.ReadFull(conn, buf2[:2])
	if err != nil {
		return nil, err
	}
	addr.Port = (int(buf2[0]) << 8) + int(buf2[1])
	log.Infof("UDP ASSOCIATE handshake done, server addr: %s", addr)

	// Prepare local socket for UDP connection
	udpConn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, err
	}

	return &socks5udpconn{
		tcpConn: conn,
		udpConn: udpConn,
		udpAddr: addr,
	}, nil
}

func (p *socks5udpconn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	log.Infof("socks5udpconn.ReadFrom localAddr=%s", p.udpConn.LocalAddr())
	buf := bufPool.Get().([]byte)
	for {
		n2, addr2, err2 := p.udpConn.ReadFromUDP(buf)
		if err2 != nil {
			return 0, nil, err2
		}
		buf2 := buf[:n2]
		if addr2.Port != p.udpAddr.Port || bytes.Compare(addr2.IP, p.udpAddr.IP) != 0 {
			log.Warningf("Dropping UDP packet from %s", addr2)
			continue
		}
		if len(buf2) < 4 || buf2[0] != 0 || buf2[1] != 0 || buf2[2] != 0 {
			log.Error("Invalid UDP packet from server")
			continue
		}
		udpAddr := &net.UDPAddr{}
		switch buf2[3] {
		case 1:
			if len(buf2) < 8 {
				log.Error("Invalid UDP packet from server")
				continue
			}
			udpAddr.IP = make([]byte, 4)
			copy(udpAddr.IP, buf2[4:8])
			buf2 = buf2[8:]
		case 4:
			if len(buf2) < 20 {
				log.Error("Invalid UDP packet from server")
				continue
			}
			udpAddr.IP = make([]byte, 16)
			copy(udpAddr.IP, buf2[4:20])
			buf2 = buf2[20:]
		default:
			log.Error("Invalid UDP packet from server")
			continue
		}
		if len(buf2) < 2 {
			log.Error("Invalid UDP packet from server")
			continue
		}
		udpAddr.Port = (int(buf2[0]) << 8) + int(buf2[1])
		buf2 = buf2[2:]
		n = copy(b, buf2)
		if n < len(buf2) {
			err = io.ErrShortBuffer
		}
		addr = udpAddr
		fmt.Println(hex.Dump(b))
		bufPool.Put(buf)
		return
	}
}

func (p *socks5udpconn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	log.Infof("socks5udpconn.WriteTo localAddr=%s", p.udpConn.LocalAddr())
	var udpAddr *net.UDPAddr
	var ok bool
	if udpAddr, ok = addr.(*net.UDPAddr); !ok {
		udpAddr, err = net.ResolveUDPAddr(addr.Network(), addr.String())
		if err != nil {
			return
		}
	}

	buf := bufPool.Get().([]byte)
	defer bufPool.Put(buf)
	buf2 := bytes.NewBuffer(buf[:0])
	buf2.WriteByte(0)
	buf2.WriteByte(0)
	buf2.WriteByte(0)
	encodeAddr(buf2, udpAddr)
	buf2.Write(b)
	return p.udpConn.Write(buf2.Bytes())
}

func (p *socks5udpconn) Close() error {
	p.tcpConn.Close()
	p.udpConn.Close()
	return nil
}

func (p *socks5udpconn) LocalAddr() net.Addr {
	return p.udpConn.LocalAddr()
}

func (p *socks5udpconn) SetDeadline(t time.Time) error {
	return p.udpConn.SetDeadline(t)
}

func (p *socks5udpconn) SetReadDeadline(t time.Time) error {
	return p.udpConn.SetReadDeadline(t)
}

func (p *socks5udpconn) SetWriteDeadline(t time.Time) error {
	return p.udpConn.SetWriteDeadline(t)
}
