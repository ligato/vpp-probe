package agent

import (
	"strings"
	"testing"

	vpp_interfaces "go.ligato.io/vpp-agent/v3/proto/ligato/vpp/interfaces"
)

func Test_interfaceInfo(t *testing.T) {
	coloredOutput = false

	type args struct {
		iface VppInterface
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "memif",
			args: args{iface: VppInterface{
				Value: &vpp_interfaces.Interface{
					Name: "memif",
					Type: vpp_interfaces.Interface_MEMIF,
					Link: &vpp_interfaces.Interface_Memif{
						Memif: &vpp_interfaces.MemifLink{
							Id:             1,
							SocketFilename: "/tmp/memif.sock",
						},
					},
				},
			}},
			want: "socket:/tmp/memif.sock id:1",
		},
		{
			name: "tap",
			args: args{iface: VppInterface{
				KVData: KVData{
					Metadata: map[string]interface{}{
						"TAPHostIfName": "tapx",
					},
				},
				Value: &vpp_interfaces.Interface{
					Name: "tap",
					Type: vpp_interfaces.Interface_TAP,
					Link: &vpp_interfaces.Interface_Tap{
						Tap: &vpp_interfaces.TapLink{
							Version: 2,
						},
					},
				},
			}},
			want: "host_if_name:tapx version:2",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := interfaceInfo(tt.args.iface); strings.TrimSpace(got) != tt.want {
				t.Errorf("interfaceInfo() = %v, want %v", got, tt.want)
			}
		})
	}
}
