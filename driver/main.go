package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"

	"github.com/gorilla/mux"
)

type Driver struct {
	ProxyAddr  string
	SocketAddr string
	TableName  string

	mu       sync.Mutex
	networks map[string]*network
}

func main() {
	d := &Driver{}
	d.networks = make(map[string]*network)
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
	// Policy routing
	if err := d.setupIP(); err != nil {
		log.Fatalf("failed to setup IP rules: %s", err)
		return
	}
	defer func() {
		if err := d.unsetupIP(); err != nil {
			fmt.Println("failed to unsetup IP rules: %s", err)
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
