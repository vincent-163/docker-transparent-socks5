package main

import (
	"github.com/vincent-163/docker-transparent-socks5/netop"
)

func (d *Driver) setupIP() error {
	if err := netop.ExecCmd("ip", "rule", "add", "fwmark", "1", "lookup", d.TableName); err != nil {
		return err
	}
	if err := netop.ExecCmd("ip", "route", "add", "local", "default", "dev", "lo", "table", d.TableName); err != nil {
		return err
	}
	return nil
}

func (d *Driver) unsetupIP() error {
	if err := netop.ExecCmd("ip", "rule", "del", "fwmark", "1", "lookup", d.TableName); err != nil {
		return err
	}
	if err := netop.ExecCmd("ip", "route", "del", "local", "default", "dev", "lo", "table", d.TableName); err != nil {
		return err
	}
	return nil
}
