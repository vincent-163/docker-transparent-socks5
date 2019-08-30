package main

import (
	"crypto/rand"
	"encoding/hex"
)

func newRandomHex(n int) string {
	data := make([]byte, n)
	if _, err := rand.Read(data[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(data)
}
