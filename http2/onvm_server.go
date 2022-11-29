package http2

import (
	"crypto/tls"
	"fmt"
	"math"
	"net"
	"time"

	"github.com/nycu-ucr/net/http2/hpack"
)

// ServeConn serves HTTP/2 requests on the provided connection and
// blocks until the connection is no longer readable.
//
// ServeConn starts speaking HTTP/2 assuming that c has not had any
// reads or writes. It writes its initial settings frame and expects
// to be able to read the preface and settings frame from the
// client. If c has a ConnectionState method like a *tls.Conn, the
// ConnectionState is used to verify the TLS ciphersuite and to set
// the Request.TLS field in Handlers.
//
// ServeConn does not support h2c by itself. Any h2c support must be
// implemented in terms of providing a suitably-behaving net.Conn.
//
// The opts parameter is optional. If nil, default values are used.
func (s *Server) ServeOnvmConn(c net.Conn, opts *ServeConnOpts) {
	baseCtx, cancel := serverConnBaseContext(c, opts)
	defer cancel()

	sc := &serverConn{
		srv:                         s,
		hs:                          opts.baseConfig(),
		conn:                        c,
		baseCtx:                     baseCtx,
		remoteAddrStr:               c.RemoteAddr().String(),
		bw:                          newBufferedWriter(c),
		handler:                     opts.handler(),
		streams:                     make(map[uint32]*stream),
		readFrameCh:                 make(chan readFrameResult),
		wantWriteFrameCh:            make(chan FrameWriteRequest, 8),
		serveMsgCh:                  make(chan interface{}, 8),
		wroteFrameCh:                make(chan frameWriteResult, 1), // buffered; one send in writeFrameAsync
		bodyReadCh:                  make(chan bodyReadMsg),         // buffering doesn't matter either way
		doneServing:                 make(chan struct{}),
		clientMaxStreams:            math.MaxUint32, // Section 6.5.2: "Initially, there is no limit to this value"
		advMaxStreams:               s.maxConcurrentStreams(),
		initialStreamSendWindowSize: initialWindowSize,
		maxFrameSize:                initialMaxFrameSize,
		headerTableSize:             initialHeaderTableSize,
		serveG:                      newGoroutineLock(),
		pushEnabled:                 true,
		sawClientPreface:            opts.SawClientPreface,
	}

	s.state.registerConn(sc)
	defer s.state.unregisterConn(sc)

	// The net/http package sets the write deadline from the
	// http.Server.WriteTimeout during the TLS handshake, but then
	// passes the connection off to us with the deadline already set.
	// Write deadlines are set per stream in serverConn.newStream.
	// Disarm the net.Conn write deadline here.
	if sc.hs.WriteTimeout != 0 {
		sc.conn.SetWriteDeadline(time.Time{})
	}

	if s.NewWriteScheduler != nil {
		sc.writeSched = s.NewWriteScheduler()
	} else {
		sc.writeSched = NewPriorityWriteScheduler(nil)
	}

	// These start at the RFC-specified defaults. If there is a higher
	// configured value for inflow, that will be updated when we send a
	// WINDOW_UPDATE shortly after sending SETTINGS.
	sc.flow.add(initialWindowSize)
	sc.inflow.add(initialWindowSize)
	sc.hpackEncoder = hpack.NewEncoder(&sc.headerWriteBuf)

	fr := NewFramer(sc.bw, c)
	if s.CountError != nil {
		fr.countError = s.CountError
	}
	fr.ReadMetaHeaders = hpack.NewDecoder(initialHeaderTableSize, nil)
	fr.MaxHeaderListSize = sc.maxHeaderListSize()
	fr.SetMaxReadFrameSize(s.maxReadFrameSize())
	sc.framer = fr

	if tc, ok := c.(connectionStater); ok {
		sc.tlsState = new(tls.ConnectionState)
		*sc.tlsState = tc.ConnectionState()
		// 9.2 Use of TLS Features
		// An implementation of HTTP/2 over TLS MUST use TLS
		// 1.2 or higher with the restrictions on feature set
		// and cipher suite described in this section. Due to
		// implementation limitations, it might not be
		// possible to fail TLS negotiation. An endpoint MUST
		// immediately terminate an HTTP/2 connection that
		// does not meet the TLS requirements described in
		// this section with a connection error (Section
		// 5.4.1) of type INADEQUATE_SECURITY.
		if sc.tlsState.Version < tls.VersionTLS12 {
			sc.rejectConn(ErrCodeInadequateSecurity, "TLS version too low")
			return
		}

		if sc.tlsState.ServerName == "" {
			// Client must use SNI, but we don't enforce that anymore,
			// since it was causing problems when connecting to bare IP
			// addresses during development.
			//
			// TODO: optionally enforce? Or enforce at the time we receive
			// a new request, and verify the ServerName matches the :authority?
			// But that precludes proxy situations, perhaps.
			//
			// So for now, do nothing here again.
		}

		if !s.PermitProhibitedCipherSuites && isBadCipher(sc.tlsState.CipherSuite) {
			// "Endpoints MAY choose to generate a connection error
			// (Section 5.4.1) of type INADEQUATE_SECURITY if one of
			// the prohibited cipher suites are negotiated."
			//
			// We choose that. In my opinion, the spec is weak
			// here. It also says both parties must support at least
			// TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 so there's no
			// excuses here. If we really must, we could allow an
			// "AllowInsecureWeakCiphers" option on the server later.
			// Let's see how it plays out first.
			sc.rejectConn(ErrCodeInadequateSecurity, fmt.Sprintf("Prohibited TLS 1.2 Cipher Suite: %x", sc.tlsState.CipherSuite))
			return
		}
	}

	if opts.Settings != nil {
		fr := &SettingsFrame{
			FrameHeader: FrameHeader{valid: true},
			p:           opts.Settings,
		}
		if err := fr.ForeachSetting(sc.processSetting); err != nil {
			sc.rejectConn(ErrCodeProtocol, "invalid settings")
			return
		}
		opts.Settings = nil
	}

	if hook := testHookGetServerConn; hook != nil {
		hook(sc)
	}

	if opts.UpgradeRequest != nil {
		sc.upgradeRequest(opts.UpgradeRequest)
		opts.UpgradeRequest = nil
	}

	buff := make([]byte, 10240)
	n, err := sc.conn.Read(buff)

	if err != nil {
		println("x/net/http2/server.go/ServeConn: net.Conn.Read -> %d bytes", n)
	}
	println("x/net/http2/server.go/ServeConn: net.Conn.Read error -> %+v", err)

	req, err := DecodeRequest(buff)

	st := sc.newStream(0, 0, stateOpen)

	rw := sc.newResponseWriter(st, req.Request)

	sc.runHandler(rw, req.Request, sc.handler.ServeHTTP)

	// sc.serve()
}