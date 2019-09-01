package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
)

func main() {
	conn, err := net.Dial("tcp", "127.0.0.1:1081")
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	buf := make([]byte, 65536)
	go func() {
		for {
			n, err := conn.Read(buf)
			if err != nil {
				panic(err)
			}
			fmt.Println(hex.Dump(buf[:n]))
		}
	}()
	scanner := bufio.NewReader(os.Stdin)
	for {
		s, err := scanner.ReadString('\n')
		if err != nil {
			panic(err)
		}
		h, err := hex.DecodeString(strings.Trim(s, "\n"))
		if err != nil {
			panic(err)
		}
		n, err := conn.Write(h)
		if n != len(h) {
			panic(err)
		}
	}
	/*
		n, err := conn.Write([]byte{5, 1, 0, 5, 3, })
		if n != 3 {
			panic(err)
		}
		time.Sleep(time.Second * 10)
	*/
}
