package vpp

import (
	"bytes"
	"encoding/json"

	"github.com/goccy/go-yaml"
	"github.com/k0kubun/pp"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
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
