/*
Copyright 2017 Frederic Branczyk All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func initTransport(upstreamURL url.URL, upstreamCAFile string) (http.RoundTripper, url.URL, error) {
	transport := http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	if upstreamCAFile != "" {
		rootPEM, err := ioutil.ReadFile(upstreamCAFile)
		if err != nil {
			return nil, upstreamURL, fmt.Errorf("error reading upstream CA file: %v", err)
		}

		roots := x509.NewCertPool()
		if ok := roots.AppendCertsFromPEM([]byte(rootPEM)); !ok {
			return nil, upstreamURL, errors.New("error parsing upstream CA certificate")
		}
		// http.Transport sourced from go 1.10.7
		transport.TLSClientConfig = &tls.Config{RootCAs: roots}
	}

	if upstreamURL.Scheme == "unix" {
		parts := strings.SplitN(upstreamURL.Path, ":", 2)
		if len(parts) == 1 {
			parts = append(parts, "/")
		}
		transport.DialContext = func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", parts[0])
		}

		parsedURL, err := url.Parse("http://unix" + parts[1])
		if err != nil {
			return nil, upstreamURL, fmt.Errorf("error while deconding unix socket path url: %v", err)
		}
		upstreamURL = *parsedURL
	}

	return &transport, upstreamURL, nil
}
