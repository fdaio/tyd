package transport

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"time"
)

func ListenUnix(path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		return nil, err
	}
	return &unixListener{Listener: ln, path: path}, nil
}

type unixListener struct {
	net.Listener
	path string
}

func (l *unixListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return Wrap(c, Info{
		Transport: KindUnix,
		TLS:       false,
	}), nil
}

func (l *unixListener) Close() error {
	err := l.Listener.Close()
	_ = os.Remove(l.path)
	return err
}

func DialUnix(path string) (Conn, error) {
	return DialUnixContext(context.Background(), path)
}

func DialUnixContext(ctx context.Context, path string) (Conn, error) {
	d := &net.Dialer{Timeout: 3 * time.Second}
	c, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	return Wrap(c, Info{
		Transport: KindUnix,
		TLS:       false,
	}), nil
}
