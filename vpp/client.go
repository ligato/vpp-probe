package vpp

import (
	"context"
	"errors"

	govppapi "git.fd.io/govpp.git/api"
	"github.com/sirupsen/logrus"
	"go.ligato.io/vpp-agent/v3/plugins/govppmux/vppcalls"
	"go.ligato.io/vpp-agent/v3/plugins/vpp"
)

var (
	ErrStatsUnavailable = errors.New("Stats unavailable")
	ErrAPIUnavailable   = errors.New("API unavailable")
	ErrCLIUnavailable   = errors.New("CLI unavailable")
)

type vppClient struct {
	//conn    *govppcore.Connection
	vppConn govppapi.Connection
	ch      govppapi.Channel
	stats   govppapi.StatsProvider
	vpp     vppcalls.VppCoreAPI
	version vpp.Version
}

func newVppClient() *vppClient {
	return &vppClient{
		ch:      nil,
		stats:   nil,
		vpp:     nil,
		version: "",
	}
}

func (v *vppClient) NewStream(ctx context.Context, options ...govppapi.StreamOption) (govppapi.Stream, error) {
	return v.vppConn.NewStream(ctx, options...)
}

func (v *vppClient) Invoke(ctx context.Context, req govppapi.Message, reply govppapi.Message) error {
	return v.vppConn.Invoke(ctx, req, reply)
}

func (v *vppClient) NewAPIChannel() (govppapi.Channel, error) {
	return v.ch, nil
}

func (v *vppClient) Version() vpp.Version {
	return v.version
}

func (v *vppClient) BinapiVersion() vpp.Version {
	return v.version
}

func (v *vppClient) CheckCompatiblity(msgs ...govppapi.Message) error {
	return v.ch.CheckCompatiblity(msgs...)
}

func (v *vppClient) Stats() govppapi.StatsProvider {
	return v.stats
}

func (v *vppClient) IsPluginLoaded(plugin string) bool {
	ctx := context.Background()
	plugins, err := v.vpp.GetPlugins(ctx)
	if err != nil {
		logrus.Warnf("GetPlugins failed: %v", plugins)
		return false
	}
	for _, p := range plugins {
		if p.Name == plugin {
			return true
		}
	}
	return false
}

func (v *vppClient) OnReconnect(h func()) {
	// no-op
}
