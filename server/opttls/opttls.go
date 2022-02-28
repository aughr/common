package opttls

import (
	"bytes"
	"crypto/tls"
	"errors"
	"golang.org/x/net/http2"
	"google.golang.org/grpc/credentials"
	"io"
	"net"
	"net/http"
)

type listener struct {
	net.Listener
	config *tls.Config
}

// Listen creates an _optional_ TLS listener accepting connections on the
// given network address using net.Listen.
// The configuration config must be non-nil and must include
// at least one certificate or else set GetCertificate.
func Listen(network, laddr string, config *tls.Config) (net.Listener, error) {
	if config == nil || len(config.Certificates) == 0 &&
		config.GetCertificate == nil && config.GetConfigForClient == nil {
		return nil, errors.New("opttls: neither Certificates, GetCertificate, nor GetConfigForClient set in Config")
	}
	l, err := net.Listen(network, laddr)
	if err != nil {
		return nil, err
	}
	return NewListener(l, config), nil
}

func NewListener(l net.Listener, config *tls.Config) net.Listener {
	return &listener{l, config}
}

type optTLSErr struct {
	err string
}

func (e optTLSErr) Error() string   { return e.err }
func (e optTLSErr) Timeout() bool   { return false }
func (e optTLSErr) Temporary() bool { return true }

var _ net.Error = optTLSErr{}

func (l *listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	c, isTLS, err := PeekTLS(c)
	if err != nil {
		return nil, err
	}

	if isTLS {
		return tls.Server(c, l.config), nil
	}
	return c, nil
}

type peekedConn struct {
	net.Conn
	r io.Reader
}

func (c *peekedConn) Read(b []byte) (int, error) {
	return c.r.Read(b)
}

func PeekTLS(c net.Conn) (net.Conn, bool, error) {
	b := make([]byte, 2)
	n, err := c.Read(b)
	if err != nil {
		cerr := c.Close()
		if cerr != nil {
			return nil, false, err
		}
		return nil, false, optTLSErr{err.Error()}
	}
	if n < 2 {
		err := c.Close()
		if err != nil {
			return nil, false, err
		}
		return nil, false, optTLSErr{"EOF"}
	}

	tlsFrameType := b[0]
	tlsMajorVersion := b[1]
	//isTLS := (tlsFrameType == TLS_HANDSHAKE_FRAME_TYPE || tlsFrameType == TLS_ALERT_FRAME_TYPE) && tlsMajorVersion == TLS_MAJOR_VERSION;
	isTLS := (tlsFrameType == 0x15 || tlsFrameType == 0x16) && tlsMajorVersion == 3

	c = &peekedConn{c, io.MultiReader(bytes.NewBuffer(b), c)}
	return c, isTLS, nil
}
func ServeTLSOptionally(srv *http.Server, l net.Listener, certFile, keyFile string) error {
	err := http2.ConfigureServer(srv, nil)
	if err != nil {
		return err
	}

	config := cloneTLSConfig(srv.TLSConfig)
	if !strSliceContains(config.NextProtos, "http/1.1") {
		config.NextProtos = append(config.NextProtos, "http/1.1")
	}

	configHasCert := len(config.Certificates) > 0 || config.GetCertificate != nil
	if !configHasCert || certFile != "" || keyFile != "" {
		var err error
		config.Certificates = make([]tls.Certificate, 1)
		config.Certificates[0], err = tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return err
		}
	}

	return srv.Serve(NewListener(l, config))
}

func cloneTLSConfig(cfg *tls.Config) *tls.Config {
	if cfg == nil {
		return &tls.Config{}
	}
	return cfg.Clone()
}

func strSliceContains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

type Creds struct {
	credentials.TransportCredentials
}

func (c *Creds) ServerHandshake(rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	rawConn, isTLS, err := PeekTLS(rawConn)
	if err != nil {
		return nil, nil, err
	}
	if isTLS {
		return c.TransportCredentials.ServerHandshake(rawConn)
	}
	return rawConn, nil, nil
}
