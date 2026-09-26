package relay

import (
	"fmt"
	"net"
)

// ListenAndServe accepts TCP connections and runs the rendezvous hub.
func ListenAndServe(addr string) (net.Addr, func() error, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, err
	}
	hub := NewHub()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go hub.Handle(c)
		}
	}()
	return ln.Addr(), ln.Close, nil
}

// MustListen is a convenience for tests.
func MustListen(addr string) (net.Addr, func() error) {
	a, closeFn, err := ListenAndServe(addr)
	if err != nil {
		panic(fmt.Sprintf("relay listen: %v", err))
	}
	return a, closeFn
}
