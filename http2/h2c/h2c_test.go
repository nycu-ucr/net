// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package h2c

import (
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"strings"
	"testing"

	"github.com/nycu-ucr/gonet/http"
	"github.com/nycu-ucr/gonet/http/httptest"
	"github.com/nycu-ucr/net/http2"
)

func ExampleNewHandler() {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "Hello world")
	})
	h2s := &http2.Server{
		// ...
	}
	h1s := &http.Server{
		Addr:    ":8080",
		Handler: NewHandler(handler, h2s),
	}
	log.Fatal(h1s.ListenAndServe())
}

func TestContext(t *testing.T) {
	baseCtx := context.WithValue(context.Background(), "testkey", "testvalue")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Errorf("Request wasn't handled by h2c.  Got ProtoMajor=%v", r.ProtoMajor)
		}
		if r.Context().Value("testkey") != "testvalue" {
			t.Errorf("Request doesn't have expected base context: %v", r.Context())
		}
		fmt.Fprint(w, "Hello world")
	})

	h2s := &http2.Server{}
	h1s := httptest.NewUnstartedServer(NewHandler(handler, h2s))
	h1s.Config.BaseContext = func(_ net.Listener) context.Context {
		return baseCtx
	}
	h1s.Start()
	defer h1s.Close()

	client := &http.Client{
		Transport: &http2.Transport{
			AllowHTTP: true,
			DialTLS: func(network, addr string, _ *tls.Config) (net.Conn, error) {
				return net.Dial(network, addr)
			},
		},
	}

	resp, err := client.Get(h1s.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestPropagation(t *testing.T) {
	var (
		server *http.Server
		// double the limit because http2 will compress header
		headerSize  = 1 << 11
		headerLimit = 1 << 10
	)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Errorf("Request wasn't handled by h2c.  Got ProtoMajor=%v", r.ProtoMajor)
		}
		if r.Context().Value(http.ServerContextKey).(*http.Server) != server {
			t.Errorf("Request doesn't have expected http server: %v", r.Context())
		}
		if len(r.Header.Get("Long-Header")) != headerSize {
			t.Errorf("Request doesn't have expected http header length: %v", len(r.Header.Get("Long-Header")))
		}
		fmt.Fprint(w, "Hello world")
	})

	h2s := &http2.Server{}
	h1s := httptest.NewUnstartedServer(NewHandler(handler, h2s))

	server = h1s.Config
	server.MaxHeaderBytes = headerLimit
	server.ConnState = func(conn net.Conn, state http.ConnState) {
		t.Logf("server conn state: conn %s -> %s, status changed to %s", conn.RemoteAddr(), conn.LocalAddr(), state)
	}

	h1s.Start()
	defer h1s.Close()

	client := &http.Client{
		Transport: &http2.Transport{
			AllowHTTP: true,
			DialTLS: func(network, addr string, _ *tls.Config) (net.Conn, error) {
				conn, err := net.Dial(network, addr)
				if conn != nil {
					t.Logf("client dial tls: %s -> %s", conn.RemoteAddr(), conn.LocalAddr())
				}
				return conn, err
			},
		},
	}

	req, err := http.NewRequest("GET", h1s.URL, nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Long-Header", strings.Repeat("A", headerSize))

	_, err = client.Do(req)
	if err == nil {
		t.Fatal("expected server err, got nil")
	}
}
