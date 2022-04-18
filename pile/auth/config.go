package auth

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
)

// Config for authentication
type Config struct {
	// CAPool is the pool of CAs to use for verification
	CAPool *x509.CertPool
	// Cert is the server's certificate to present to the client
	Cert tls.Certificate
}

func ServerTLSConfig(authConfig Config) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{authConfig.Cert},
		// require client certificates
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS13,
		ClientCAs:  authConfig.CAPool,
		VerifyConnection: func(cs tls.ConnectionState) error {
			// client certificate has already been verified, at this
			// stage all we're left with is some final checks

			clientCert := cs.PeerCertificates[0]
			isPilec := clientCert.Subject.CommonName == "pilec"
			if !isPilec {
				// TODO find a smarter way to verify that we
				// reach here in the tests
				logrus.Errorf("expected certificate of pilec not %q", clientCert.Subject)
				return fmt.Errorf("expected certificate of pilec not %q", clientCert.Subject)
			}
			return nil
		},
	}
}

func ClientTLSConfig(authConfig Config) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{authConfig.Cert},
		MinVersion:   tls.VersionTLS13,
		// do our own verification instead
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			// based on tls.Conn.verifyServerCertificate(), but
			// without support for intermediates and DNS name
			opts := x509.VerifyOptions{
				// ignore DNS name and intermediates
				Roots:       authConfig.CAPool,
				CurrentTime: time.Now(),
			}
			// TODO support intermediate certs, verify that the
			// current connection presented just one cert
			serverCert := cs.PeerCertificates[0]
			logrus.Tracef("server: %v", serverCert.Subject)
			_, err := cs.PeerCertificates[0].Verify(opts)
			if err != nil {
				logrus.Tracef("server certificate verify err: %v", err)
				return err
			}
			// a trivial auth check
			isPilec := serverCert.Subject.CommonName == "piled"
			if !isPilec {
				logrus.Errorf("expected certificate of pilec not %q", serverCert.Subject)
				return fmt.Errorf("expected certificate of piled not %q", serverCert.Subject)
			}
			return nil
		},
	}
}
