package proxy

import (
	"io"
	"net"
	"sync"

	"github.com/LiamHaworth/go-tproxy"
	"golang.org/x/net/proxy"
)

type TCPTProxy struct {
	UpstreamProxy proxy.Dialer
	LocalAddr     string

	tcpConn net.Listener
}

func (p *TCPTProxy) Serve() error {
	tcpAddr, err := net.ResolveTCPAddr("tcp", p.LocalAddr)
	if err != nil {
		return err
	}
	tcpConn, err := tproxy.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return err
	}
	defer func() {
		// The close operation blocks, but why?
		go tcpConn.Close()
	}()
	p.tcpConn = tcpConn

	for {
		c, err := tcpConn.Accept()
		if err != nil {
			return err
		}
		go p.serveTCPConn(c)
	}
}

func (p *TCPTProxy) Close() error {
	go p.tcpConn.Close()
	return nil
}

func (p *TCPTProxy) serveTCPConn(conn net.Conn) {
	defer conn.Close()
	log.Infof("Serving TCP connection: %s -> %s\n", conn.RemoteAddr(), conn.LocalAddr())
	conn2, err := p.UpstreamProxy.Dial("tcp", conn.LocalAddr().String())
	if err != nil {
		log.WithError(err).Error("Failed to dial upstream TCP proxy: %s")
		return
	}
	defer conn2.Close()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		io.Copy(conn, conn2)
		wg.Done()
	}()
	go func() {
		io.Copy(conn2, conn)
		wg.Done()
	}()
	wg.Wait()
}
