package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type emptyStruct struct{}

func handleError(w http.ResponseWriter, err error) {
	sendBody(w, struct {
		Err string `json:"Err"`
	}{Err: err.Error()})
}

func readBody(r *http.Request, req interface{}) error {
	var msg json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		return err
	}
	fmt.Println(string(msg))
	return json.Unmarshal(msg, req)
}

func sendBody(w http.ResponseWriter, body interface{}) {
	json.NewEncoder(w).Encode(body)
}

func (d *Driver) handlePluginActivate(w http.ResponseWriter, r *http.Request) {
	io.WriteString(w, `{ "Implements": ["NetworkDriver"] }`)
}

func (d *Driver) handleGetCapabilities(w http.ResponseWriter, r *http.Request) {
	io.WriteString(w, `{ "Scope": "local", "ConnectivityScope": "global" }`)
}

type CreateNetworkRequest struct {
	NetworkID string         `json:"NetworkID"`
	IPv4Data  []*NetworkData `json:"IPv4Data"`
	IPv6Data  []*NetworkData `json:"IPv6Data"`
}

type NetworkData struct {
	AddressSpace string            `json:"AddressSpace"`
	Pool         string            `json:"Pool"`
	Gateway      string            `json:"Gateway"`
	AuxAddresses map[string]string `json:"AuxAddresses"`
}

func (d *Driver) handleCreateNetwork(w http.ResponseWriter, r *http.Request) {
	var req CreateNetworkRequest
	if err := readBody(r, &req); err != nil {
		handleError(w, fmt.Errorf("invalid request: %s", err))
		return
	}
	data, err := json.Marshal(req)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(data))
	d.mu.Lock()
	defer d.mu.Unlock()
	var ipv4data *NetworkData
	if len(req.IPv4Data) != 0 {
		ipv4data = req.IPv4Data[0]
	}
	var ipv6data *NetworkData
	if len(req.IPv6Data) != 0 {
		ipv6data = req.IPv6Data[0]
	}
	networkId := req.NetworkID
	name := newRandomHex(6)
	net, err := d.createNetwork(name, ipv4data, ipv6data)
	if err != nil {
		handleError(w, fmt.Errorf("failed to create network: %s", err))
		return
	}
	d.networks[networkId] = net
	sendBody(w, emptyStruct{})
}

type DeleteNetworkRequest struct {
	NetworkID string `json:"NetworkID"`
}

func (d *Driver) handleDeleteNetwork(w http.ResponseWriter, r *http.Request) {
	var req DeleteNetworkRequest
	if err := readBody(r, &req); err != nil {
		handleError(w, fmt.Errorf("invalid request: %s", err))
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	networkId := req.NetworkID
	net := d.networks[networkId]
	if err := net.destroy(); err != nil {
		handleError(w, fmt.Errorf("failed to delete network: %s", err))
		return
	}
	delete(d.networks, networkId)
	sendBody(w, emptyStruct{})
}

type CreateEndpointRequest struct {
	NetworkID  string                 `json:"NetworkID"`
	EndpointID string                 `json:"EndpointID"`
	Options    map[string]interface{} `json:"Options"`
	Interface  *EndpointInterface     `json:"Interface"`
}

type EndpointInterface struct {
	Address     string `json:"Address"`
	AddressIPv6 string `json:"AddressIPv6"`
	MacAddress  string `json:"MacAddress"`
}

type CreateEndpointResponse struct {
	Interface *EndpointInterface `json:"Interface,omitempty"`
}

func (d *Driver) handleCreateEndpoint(w http.ResponseWriter, r *http.Request) {
	var req CreateEndpointRequest
	if err := readBody(r, &req); err != nil {
		handleError(w, fmt.Errorf("invalid request: %s", err))
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	networkId := req.NetworkID
	net := d.networks[networkId]
	if err := net.createEndpoint(req.EndpointID, req.Interface, req.Options); err != nil {
		handleError(w, fmt.Errorf("failed to create endpoint: %s", err))
		return
	}
	sendBody(w, emptyStruct{})
}

type NetworkEndpointRequest struct {
	NetworkID  string `json:"NetworkID"`
	EndpointID string `json:"EndpointID"`
}

type EndpointOperInfoResponse struct {
	Value map[string]interface{} `json:"Value"`
}

func (d *Driver) handleEndpointOperInfo(w http.ResponseWriter, r *http.Request) {
	var req NetworkEndpointRequest
	if err := readBody(r, &req); err != nil {
		handleError(w, fmt.Errorf("invalid request: %s", err))
		return
	}
	sendBody(w, EndpointOperInfoResponse{Value: make(map[string]interface{})})
}

func (d *Driver) handleDeleteEndpoint(w http.ResponseWriter, r *http.Request) {
	var req NetworkEndpointRequest
	if err := readBody(r, &req); err != nil {
		handleError(w, fmt.Errorf("invalid request: %s", err))
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	networkId := req.NetworkID
	net := d.networks[networkId]
	if err := net.deleteEndpoint(req.EndpointID); err != nil {
		handleError(w, fmt.Errorf("failed to delete endpoint: %s", err))
		return
	}
	sendBody(w, struct{}{})
}

type JoinRequest struct {
	NetworkID  string                 `json:"NetworkID"`
	EndpointID string                 `json:"EndpointID"`
	SandboxKey string                 `json:"SandboxKey"`
	Options    map[string]interface{} `json:"Options"`
}

type JoinResponse struct {
	InterfaceName *InterfaceNameInfo `json:"InterfaceName"`
	Gateway       string             `json:"Gateway"`
	GatewayIPv6   string             `json:"GatewayIPv6"`
	StaticRoutes  []*StaticRouteInfo `json:"StaticRoutes"`
}

type InterfaceNameInfo struct {
	SrcName   string `json:"SrcName"`
	DstPrefix string `json:"DstPrefix"`
}

type StaticRouteInfo struct {
	Destination string `json:"Destination"`
	RouteType   int    `json:"RouteType"`
	NextHop     string `json:"NextHop"`
}

func (d *Driver) handleJoin(w http.ResponseWriter, r *http.Request) {
	var req JoinRequest
	if err := readBody(r, &req); err != nil {
		handleError(w, fmt.Errorf("invalid request: %s", err))
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	networkId := req.NetworkID
	net := d.networks[networkId]
	resp, err := net.joinEndpoint(req.EndpointID, req.SandboxKey)
	if err != nil {
		handleError(w, fmt.Errorf("failed to delete endpoint: %s", err))
		return
	}
	sendBody(w, resp)
}

func (d *Driver) handleLeave(w http.ResponseWriter, r *http.Request) {
	var req NetworkEndpointRequest
	if err := readBody(r, &req); err != nil {
		handleError(w, fmt.Errorf("invalid request: %s", err))
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	networkId := req.NetworkID
	net := d.networks[networkId]
	if err := net.leaveEndpoint(req.EndpointID); err != nil {
		handleError(w, fmt.Errorf("failed to leave endpoint: %s", err))
		return
	}
	sendBody(w, struct{}{})
}
