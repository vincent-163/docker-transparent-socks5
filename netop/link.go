package netop

import (
	"os"
	"os/exec"
)

func ExecCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// Creates a bridge with name.
func CreateBridge(name string) error {
	return ExecCmd("ip", "link", "add", "dev", name, "type", "bridge")
}

// Sets the network interface with specified name up.
func SetInterfaceUp(name string) error {
	return ExecCmd("ip", "link", "set", "dev", name, "up")
}

// Creates a veth pair with one endpoint name1 and the other endpoint name2.
func CreateVeth(name1 string, name2 string) error {
	return ExecCmd("ip", "link", "add", "dev", name1, "type", "veth", "peer", "name", name2)
}

// Sets the master of an interface.
func SetMaster(name string, master string) error {
	return ExecCmd("ip", "link", "set", "dev", name, "master", master)
}

// Adds an address/address space to an interface.
func AddAddr(name string, addr string) error {
	return ExecCmd("ip", "addr", "add", addr, "dev", name)
}

// Adds an address/address space to an interface.
func AddAddrV6(name string, addr string) error {
	return ExecCmd("ip", "-6", "addr", "add", addr, "dev", name)
}

// Deletes an interface.
func DeleteInterface(name string) error {
	return ExecCmd("ip", "link", "del", "dev", name)
}

func ExecIptables(args ...string) error {
	return ExecCmd("iptables", args...)
}
