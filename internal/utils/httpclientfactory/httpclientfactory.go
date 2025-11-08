// Copyright 2025 The MathWorks, Inc.

package httpclientfactory

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"time"
)

type HttpClient interface {
	Do(request *http.Request) (*http.Response, error)
}

type HTTPClientFactory struct{}

func New() *HTTPClientFactory {
	return &HTTPClientFactory{}
}

func (f *HTTPClientFactory) NewClientForSelfSignedTLSServer(certificatePEM []byte) (HttpClient, error) {
	caCertPool := x509.NewCertPool()

	if ok := caCertPool.AppendCertsFromPEM(certificatePEM); !ok {
		return nil, fmt.Errorf("failed to append certificate to pool")
	}

	// Clock skew tolerance: allow certificates that are valid within 24 hours
	// This handles cases where system clock is slightly behind certificate time
	const clockSkewTolerance = 24 * time.Hour

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			RootCAs:           caCertPool,
			InsecureSkipVerify: true, // We perform all verification in VerifyPeerCertificate
			VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
				// Parse all certificates in the chain
				certs := make([]*x509.Certificate, 0, len(rawCerts))
				for _, rawCert := range rawCerts {
					cert, err := x509.ParseCertificate(rawCert)
					if err != nil {
						return fmt.Errorf("failed to parse certificate: %w", err)
					}
					certs = append(certs, cert)
				}

				if len(certs) == 0 {
					return fmt.Errorf("no certificates provided")
				}

				// Check certificate validity with clock skew tolerance
				now := time.Now()
				earliestValid := now.Add(-clockSkewTolerance)
				latestValid := now.Add(clockSkewTolerance)

				for _, cert := range certs {
					// Check if certificate is within clock skew tolerance
					if cert.NotBefore.After(latestValid) {
						return fmt.Errorf("certificate not yet valid: NotBefore %v is after %v (clock skew tolerance: %v)",
							cert.NotBefore, latestValid, clockSkewTolerance)
					}
					if cert.NotAfter.Before(earliestValid) {
						return fmt.Errorf("certificate expired: NotAfter %v is before %v (clock skew tolerance: %v)",
							cert.NotAfter, earliestValid, clockSkewTolerance)
					}
				}

				// Verify the certificate chain against the root CA pool
				// Try verification with current time and with clock skew adjustments
				opts := x509.VerifyOptions{
					Roots: caCertPool,
				}

				// Try verification with current time
				_, err := certs[0].Verify(opts)
				if err == nil {
					return nil
				}
				lastErr := err

				// If verification fails, try with clock skew adjustments
				// This handles cases where the certificate is valid but system time is slightly off
				for _, checkTime := range []time.Time{
					now.Add(clockSkewTolerance),
					now.Add(-clockSkewTolerance),
				} {
					opts.CurrentTime = checkTime
					_, err := certs[0].Verify(opts)
					if err == nil {
						return nil
					}
					lastErr = err
				}

				// If all verifications failed, return the last error
				return fmt.Errorf("certificate verification failed: %w", lastErr)
			},
		},
	}

	jar, err := cookiejar.New(&cookiejar.Options{})
	if err != nil {
		return nil, fmt.Errorf("failed to create cookie jar: %w", err)
	}

	return &http.Client{
		Transport: transport,
		Jar:       jar,
	}, nil
}
