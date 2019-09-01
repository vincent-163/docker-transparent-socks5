package proxy

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"

	"golang.org/x/sys/unix"
)

// Sends a UDP packet from a transparent UDP socket.
func WriteToUDP(conn *net.UDPConn, laddr *net.UDPAddr, raddr *net.UDPAddr, b []byte) (int, error) {
	log.Infof("WriteToUDP laddr=%s raddr=%s n=%d", laddr, raddr, len(b))
	buf := &bytes.Buffer{}
	var header unix.Cmsghdr
	if len(laddr.IP) == 4 && len(raddr.IP) == 4 {
		header.Level = unix.IPPROTO_IP
		header.Type = unix.IP_PKTINFO
		header.Len = unix.SizeofInet4Pktinfo
		binary.Write(buf, binary.LittleEndian, header)
		var info unix.Inet4Pktinfo
		// info.Ifindex = ?
		copy(info.Spec_dst[:], laddr.IP)
		binary.Write(buf, binary.LittleEndian, info)
	} else if len(laddr.IP) == 16 && len(raddr.IP) == 16 {
		panic("WriteToUDP: ipv6 not supported")
	} else {
		panic("WriteToUDP: invalid IP address")
	}
	n, oobn, err := conn.WriteMsgUDP(b, buf.Bytes(), raddr)
	if oobn != buf.Len() && err == nil {
		err = io.ErrShortWrite
	}
	return n, err
}
