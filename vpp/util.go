package vpp

import (
	"bytes"
	"encoding/json"

	"github.com/goccy/go-yaml"
	"github.com/k0kubun/pp"
	govppapi "go.fd.io/govpp/api"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"go.ligato.io/vpp-probe/pkg/exec"
	"go.ligato.io/vpp-probe/probe"
)

func init() {
	pp.SetColorScheme(pp.ColorScheme{
		Bool:            pp.Cyan | pp.Bold,
		Integer:         pp.Cyan,
		Float:           pp.Cyan,
		String:          pp.Green,
		StringQuotation: pp.Green,
		EscapedChar:     pp.Magenta,
		FieldName:       pp.White,
		PointerAdress:   pp.Magenta,
		Nil:             pp.Red | pp.Bold,
		Time:            pp.Blue,
		StructName:      pp.White | pp.Bold,
		ObjectLength:    pp.Blue,
	})
}

func yamlTmpl(data interface{}) (string, error) {
	out, err := encodeJson(data, "")
	if err != nil {
		return "", err
	}
	bb, err := jsonToYaml(out)
	if err != nil {
		return "", err
	}
	return string(bb), nil
}

func encodeJson(data interface{}, ident string) ([]byte, error) {
	if msg, ok := data.(proto.Message); ok {
		m := protojson.MarshalOptions{
			Indent: ident,
		}
		b, err := m.Marshal(msg)
		if err != nil {
			return nil, err
		}
		return b, nil
	}
	var b bytes.Buffer
	encoder := json.NewEncoder(&b)
	encoder.SetIndent("", ident)
	if err := encoder.Encode(data); err != nil {
		panic(err)
	}
	return b.Bytes(), nil
}

func jsonToYaml(j []byte) ([]byte, error) {
	var jsonObj interface{}
	err := yaml.UnmarshalWithOptions(j, &jsonObj, yaml.UseOrderedMap())
	if err != nil {
		return nil, err
	}
	return yaml.Marshal(jsonObj)
}

type dummyHandler struct {
	id       string
	metadata map[string]string
}

func (d *dummyHandler) Command(cmd string, args ...string) exec.Cmd {
	panic("dummy handler")
}

func (d *dummyHandler) GetCLI() (probe.CliExecutor, error) {
	panic("dummy handler")
}

func (d *dummyHandler) GetAPI() (govppapi.Channel, error) {
	panic("dummy handler")
}

func (d *dummyHandler) GetStats() (govppapi.StatsProvider, error) {
	panic("dummy handler")
}

func (d *dummyHandler) ID() string {
	return d.id
}

func (d *dummyHandler) Metadata() map[string]string {
	return d.metadata
}

func (d *dummyHandler) Close() error {
	return nil
}
