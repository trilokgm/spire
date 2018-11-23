package spireplugin

import (
	"context"
	"crypto/x509"
	"errors"
	"sync"

	"github.com/hashicorp/hcl"

	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/proto/common/plugin"
	"github.com/spiffe/spire/proto/server/upstreamca"

	"github.com/spiffe/go-spiffe/uri"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/proto/api/node"
	"google.golang.org/grpc/credentials"
	"net/url"
)

type Configuration struct {
	TTL             string `hcl:"ttl" json:"ttl"` // time to live for generated certs
	ServerAddr      string `hcl:"server_address" json:"server_address"`
	ServerPort      string `hcl:"server_port" json:"server_port"`
	ServerAgentAddr string `hcl:"server_agent_address" json:"server_agent_address"`
}

type spirePlugin struct {
	serialNumber x509util.SerialNumber
	mtx          sync.RWMutex
	creds        credentials.TransportCredentials

	trustDomain url.URL
	config      *Configuration
}

func (m *spirePlugin) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	// Parse HCL config payload into config struct
	config := Configuration{}
	if err := hcl.Decode(&config, req.Configuration); err != nil {
		return nil, err
	}

	if req.GlobalConfig == nil {
		return nil, errors.New("global configuration is required")
	}

	if req.GlobalConfig.TrustDomain == "" {
		return nil, errors.New("trust_domain is required")
	}

	if req.GlobalConfig.TrustDomain != "" {
		trustDomain, err := idutil.ParseSpiffeID("spiffe://"+req.GlobalConfig.TrustDomain, idutil.AllowAnyTrustDomain())
		if err != nil {
			return nil, err
		}
		m.trustDomain = *trustDomain
	}

	m.config = &config
	return &plugin.ConfigureResponse{}, nil
}

func (m *spirePlugin) getSpiffeIDFromSVID(svid *x509.Certificate) (string, error) {
	URIs, err := uri.GetURINamesFromCertificate(svid)
	if err != nil {
		return "", err
	}

	if len(URIs) == 0 {
		return "", errors.New("certificate does not have a spiffeId")
	}

	return URIs[0], nil
}

func (m *spirePlugin) GetPluginInfo(context.Context, *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return &plugin.GetPluginInfoResponse{}, nil
}

func (m *spirePlugin) SubmitCSR(ctx context.Context, request *upstreamca.SubmitCSRRequest) (*upstreamca.SubmitCSRResponse, error) {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	var err error
	var wKey, wCert, wBundle []byte
	var id string

	wCert, wKey, wBundle, id, err = m.getWorkloadSVID(ctx, m.config)
	if err != nil {
		return nil, err
	}

	conn, err := m.newNodeClientConn(ctx, wCert, wKey, wBundle)
	if err != nil {
		return nil, err
	}
	nodeClient := node.NewNodeClient(conn)
	defer conn.Close()

	certChain, bundle, err := m.submitCSRUpstreamCA(ctx, nodeClient, request.Csr, id)
	if err != nil {
		return nil, err
	}

	trustBundle := m.createBundleCertificate(bundle)

	return &upstreamca.SubmitCSRResponse{
		Cert:                certChain[0].Raw,
		UpstreamTrustBundle: trustBundle,
	}, nil
}

func (m *spirePlugin) createBundleCertificate(bundles *bundleutil.Bundle) []byte {
	bundle := []byte{}
	for _, c := range bundles.RootCAs() {
		bundle = append(bundle, c.Raw...)
	}
	return bundle
}

func New() (m upstreamca.Plugin) {
	return &spirePlugin{
		serialNumber: x509util.NewSerialNumber(),
	}
}
