package spireplugin

import (
	"context"
	"crypto/x509"
	"net"
	"time"

	"encoding/pem"
	"github.com/spiffe/spire/api/workload"
	proto "github.com/spiffe/spire/proto/api/workload"
	"io/ioutil"
	"os"
)

func (m *spirePlugin) getWorkloadSVID(ctx context.Context, config *Configuration) ([]byte, []byte, []byte, string, error) {
	errorChan := make(chan error, 1)

	duration, _ := time.ParseDuration(config.TTL)
	wapiClient := m.newWorkloadAPIClient(config.ServerAgentAddr, duration)
	updateChan := wapiClient.UpdateChan()
	go func() {
		err := wapiClient.Start()
		if err != nil {
			errorChan <- err
		}
	}()

	defer wapiClient.Stop()

	for {
		select {
		case svidResponse := <-updateChan:
			return m.receiveUpdatedCerts(svidResponse)
		case <-ctx.Done():
			return []byte{}, []byte{}, []byte{}, "", nil
		case err := <-errorChan:
			return []byte{}, []byte{}, []byte{}, "", err
		}
	}
}

func (m *spirePlugin) debugDumpCerts(certificate []byte, key []byte, bundle []byte) error {
	svidFile := "/tmp/test-workload-cert.crt"
	svidKeyFile := "/tmp/test-workload-cert.key"
	svidBundleFile := "/tmp/test-workload-bundle.crt"

	err := m.writeCerts(svidFile, certificate)
	if err != nil {
		return err
	}

	err = m.writeKey(svidKeyFile, key)
	if err != nil {
		return err
	}

	err = m.writeCerts(svidBundleFile, bundle)
	if err != nil {
		return err
	}

	return nil
}

// writeCerts takes a slice of bytes, which may contain multiple certificates,
// and encodes them as PEM blocks, writing them to file
func (m *spirePlugin) writeCerts(file string, data []byte) error {
	certs, err := x509.ParseCertificates(data)
	if err != nil {
		return err
	}

	pemData := []byte{}
	for _, cert := range certs {
		b := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		pemData = append(pemData, pem.EncodeToMemory(b)...)
	}

	return ioutil.WriteFile(file, pemData, os.FileMode(0766))
}

// writeKey takes a private key as a slice of bytes,
// formats as PEM, and writes it to file
func (m *spirePlugin) writeKey(file string, data []byte) error {
	b := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: data,
	}

	return ioutil.WriteFile(file, pem.EncodeToMemory(b), os.FileMode(0766))
}

func (m *spirePlugin) receiveUpdatedCerts(svidResponse *proto.X509SVIDResponse) ([]byte, []byte, []byte, string, error) {
	svid := svidResponse.Svids[0]
	return svid.X509Svid, svid.X509SvidKey, svid.Bundle, svid.SpiffeId, nil
}

//newWorkloadAPIClient creates a workload.X509Client
func (m *spirePlugin) newWorkloadAPIClient(agentAddress string, timeout time.Duration) workload.X509Client {
	addr := &net.UnixAddr{
		Net:  "unix",
		Name: agentAddress,
	}
	config := &workload.X509ClientConfig{
		Addr:    addr,
		Timeout: timeout,
	}
	return workload.NewX509Client(config)
}
