package main

import (
	"context"
	"flag"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"

	"github.com/gorilla/mux"
	"github.com/vincent-163/docker-transparent-socks5/proxy"
	gproxy "golang.org/x/net/proxy"
)

// Copied from golang.org/x/net/proxy.Dialer
type Dialer interface {
	Dial(network, addr string) (c net.Conn, err error)
}

type Driver struct {
	ProxyNetwork string
	ProxyAddr    string
	SocketAddr   string
	TableName    string

	mu       sync.Mutex
	tcpProxy Dialer
	udpProxy *proxy.SOCKS5Proxy
	networks map[string]*network
}

func main() {
	d := &Driver{}
	d.networks = make(map[string]*network)
	d.ProxyNetwork = "tcp"
	flag.StringVar(&d.ProxyAddr, "proxy", "", "Address of SOCKS5 proxy")
	flag.StringVar(&d.SocketAddr, "socket", "/run/docker/plugins/socks5.sock", "Path of unix socket")
	flag.StringVar(&d.TableName, "table", "30", "Table name for IP routes, change when conflict occurs")
	flag.Parse()
	addr := &net.UnixAddr{Name: d.SocketAddr, Net: "unix"}
	listener, err := net.ListenUnix("unix", addr)
	if err != nil {
		log.Fatalf("failed to listen on unix socket: %s", err)
		return
	}
	// Prepare SOCKS5 proxy
	tcpProxy, err := gproxy.SOCKS5(d.ProxyNetwork, d.ProxyAddr, nil, &net.Dialer{})
	if err != nil {
		log.Fatalf("failed to prepare SOCKS5 proxy: %s", err)
		return
	}
	d.tcpProxy = tcpProxy
	udpProxy, err := proxy.NewSOCKS5Proxy(d.ProxyNetwork, d.ProxyAddr)
	if err != nil {
		log.Fatalf("failed to prepare SOCKS5 proxy: %s", err)
		return
	}
	d.udpProxy = udpProxy
	if err := ioutil.WriteFile("/proc/sys/net/bridge/bridge-nf-call-iptables", []byte("0"), 0644); err != nil && !os.IsNotExist(err) {
		log.Warning("failed to tune /proc/sys/net/bridge/bridge-nf-call-iptables to 0")
	}
	// Setup policy routing
	if err := d.setupIP(); err != nil {
		log.WithError(err).Warningf("failed to setup IP rules")
	}
	defer func() {
		if err := d.unsetupIP(); err != nil {
			log.WithError(err).Warningf("failed to unsetup IP rules")
		}
	}()

	m := mux.NewRouter()
	m.HandleFunc("/Plugin.Activate", d.handlePluginActivate)
	m.HandleFunc("/NetworkDriver.GetCapabilities", d.handleGetCapabilities)
	m.HandleFunc("/NetworkDriver.CreateNetwork", d.handleCreateNetwork)
	m.HandleFunc("/NetworkDriver.DeleteNetwork", d.handleDeleteNetwork)
	m.HandleFunc("/NetworkDriver.CreateEndpoint", d.handleCreateEndpoint)
	m.HandleFunc("/NetworkDriver.EndpointOperInfo", d.handleEndpointOperInfo)
	m.HandleFunc("/NetworkDriver.DeleteEndpoint", d.handleDeleteEndpoint)
	m.HandleFunc("/NetworkDriver.Join", d.handleJoin)
	m.HandleFunc("/NetworkDriver.Leave", d.handleLeave)
	server := &http.Server{}
	server.Handler = m
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	go func() {
		<-ch
		server.Shutdown(context.TODO())
	}()
	if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Failed to serve HTTP: %s", err)
	}
}
