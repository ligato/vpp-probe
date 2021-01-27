module go.ligato.io/vpp-probe

go 1.14

require (
	git.fd.io/govpp.git v0.3.6-0.20201104125301-2b743eede78b
	github.com/docker/docker v0.0.0-20180620002508-3dfb26ab3cbf
	github.com/fsouza/go-dockerclient v1.2.2
	github.com/gdamore/tcell/v2 v2.0.1-0.20201019142633-1057d5591ed1
	github.com/go-stack/stack v1.8.0
	github.com/goccy/go-yaml v1.8.0
	github.com/gookit/color v1.3.2
	github.com/imdario/mergo v0.3.11 // indirect
	github.com/k0kubun/colorstring v0.0.0-20150214042306-9440f1994b88 // indirect
	github.com/k0kubun/pp v3.0.1+incompatible
	github.com/mitchellh/go-ps v0.0.0-20170309133038-4fdf99ab2936
	github.com/segmentio/textio v1.2.0
	github.com/sirupsen/logrus v1.6.0
	github.com/spf13/cobra v1.0.0
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.4.0
	gitlab.com/tslocum/cview v1.5.1
	go.ligato.io/cn-infra/v2 v2.5.0-alpha.0.20200313154441-b0d4c1b11c73
	go.ligato.io/vpp-agent/v3 v3.2.0
	google.golang.org/protobuf v1.24.0
	k8s.io/api v0.18.15
	k8s.io/apimachinery v0.18.15
	k8s.io/cli-runtime v0.18.15
	k8s.io/client-go v0.18.15
	k8s.io/klog v1.0.0
	k8s.io/utils v0.0.0-20200731180307-f00132d28269 // indirect
)

replace (
	k8s.io/api => k8s.io/api v0.18.15
	k8s.io/apimachinery => k8s.io/apimachinery v0.18.15
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.18.15
	k8s.io/client-go => k8s.io/client-go v0.18.15
)
