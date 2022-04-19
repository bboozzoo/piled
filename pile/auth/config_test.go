package auth_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bboozzoo/piled/pile/auth"
	"github.com/bboozzoo/piled/testutils"
)

func loadCert(t *testing.T, from string) *x509.Certificate {
	d, err := os.ReadFile(from)
	require.NoError(t, err)
	pemCertBlock, _ := pem.Decode(d)
	require.NotNil(t, pemCertBlock, "pem block is nil")
	cert, err := x509.ParseCertificate(pemCertBlock.Bytes)
	require.NoError(t, err)
	return cert
}

func TestServerConfig(t *testing.T) {
	testutils.MockLogger(t)

	caCert := loadCert(t, "../../testdata/ca-cert.pem")
	cert, err := tls.LoadX509KeyPair("../../testdata/server-cert.pem",
		"../../testdata/server-key.pem")
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	conf := auth.ServerTLSConfig(auth.Config{
		Cert:   cert,
		CAPool: pool,
	})
	require.NotNil(t, conf)
	// root CAs are set
	assert.Equal(t, pool, conf.ClientCAs)
	assert.EqualValues(t, tls.VersionTLS13, conf.MinVersion)
	assert.Equal(t, tls.RequireAndVerifyClientCert, conf.ClientAuth)
	assert.Len(t, conf.Certificates, 1)
	assert.Equal(t, cert, conf.Certificates[0])

	require.NotNil(t, conf.VerifyConnection)
	validClientCert := loadCert(t, "../../testdata/client-cert.pem")
	invalidNotPilecClientCert := loadCert(t, "../../testdata/client-not-pilec-cert.pem")
	// TODO tst with invalid client cert

	// XXX this executes only limited verification without checking the CA
	err = conf.VerifyConnection(tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{validClientCert},
	})
	require.NoError(t, err)

	err = conf.VerifyConnection(tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{invalidNotPilecClientCert},
	})
	require.EqualError(t, err, fmt.Sprintf(`expected certificate of pilec not %q`,
		invalidNotPilecClientCert.Subject))
}

func TestClientConfig(t *testing.T) {
	testutils.MockLogger(t)

	caCert := loadCert(t, "../../testdata/ca-cert.pem")
	cert, err := tls.LoadX509KeyPair("../../testdata/client-cert.pem",
		"../../testdata/client-key.pem")
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	conf := auth.ClientTLSConfig(auth.Config{
		Cert:   cert,
		CAPool: pool,
	})
	require.NotNil(t, conf)
	assert.Nil(t, conf.ClientCAs)
	assert.EqualValues(t, tls.VersionTLS13, conf.MinVersion)
	assert.Len(t, conf.Certificates, 1)
	assert.Equal(t, cert, conf.Certificates[0])

	require.NotNil(t, conf.VerifyConnection)
	validServerCert := loadCert(t, "../../testdata/server-cert.pem")
	invalidNotPiledServerCert := loadCert(t, "../../testdata/server-not-piled-cert.pem")
	invalidServerCert := loadCert(t, "../../testdata/invalid-server-cert.pem")
	err = conf.VerifyConnection(tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{validServerCert},
	})
	require.NoError(t, err)

	err = conf.VerifyConnection(tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{invalidNotPiledServerCert},
	})
	require.EqualError(t, err, fmt.Sprintf(`expected certificate of piled not %q`,
		invalidNotPiledServerCert.Subject))

	err = conf.VerifyConnection(tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{invalidServerCert},
	})
	require.Error(t, err)
	assert.Regexp(t, `x509: certificate signed by unknown authority .*`, err.Error())
}
