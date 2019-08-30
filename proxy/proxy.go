package proxy

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/LiamHaworth/go-tproxy"
)

type Proxy struct {
	ProxyNetwork string
	ProxyAddr    string
	LocalAddr    string

	cancel func()
}

func (p *Proxy) Serve() error {
	ctx, cancel := context.WithCancel(context.Background())
	tcpAddr, err := net.ResolveTCPAddr("tcp", p.LocalAddr)
	if err != nil {
		return err
	}
	udpAddr, err := net.ResolveUDPAddr("udp", p.LocalAddr)
	if err != nil {
		return err
	}
	tcpConn, err := tproxy.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return err
	}
	defer tcpConn.Close()
	udpConn, err := tproxy.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	defer udpConn.Close()
	fmt.Printf("Listening on tcp/udp %s\n", p.LocalAddr)
	p.cancel = func() {
		cancel()
		// TODO: these close operations block?
		go tcpConn.Close()
		go udpConn.Close()
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		p.serveTCP(ctx, tcpConn)
		wg.Done()
	}()
	go func() {
		p.serveUDP(ctx, udpConn)
		wg.Done()
	}()
	wg.Wait()
	return nil
}

func (p *Proxy) Close() error {
	p.cancel()
	return nil
}

func (p *Proxy) handleError(err error) {
	fmt.Println(err)
}

func (p *Proxy) serveTCP(ctx context.Context, conn net.Listener) {
	fmt.Println("in serveTCP")
	for {
		c, err := conn.Accept()
		if err != nil {
			p.handleError(err)
			return
		}
		go p.serveTCPConn(c)
	}
}

func (p *Proxy) serveTCPConn(conn net.Conn) {
	fmt.Printf("Serving TCP connection: %s -> %s\n", conn.LocalAddr(), conn.RemoteAddr())
	conn.Close()
}

func (p *Proxy) serveUDP(ctx context.Context, conn *net.UDPConn) {
	fmt.Println("in serveUDP")
	buf := make([]byte, 65536)
	for {
		n, local, remote, err := tproxy.ReadFromUDP(conn, buf)
		if err != nil {
			p.handleError(err)
			return
		}
		fmt.Printf("Serving UDP packet: %s -> %s, size=%d\n", local, remote, n)
	}
}
