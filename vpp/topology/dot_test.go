package topology

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"testing"

	"go.ligato.io/vpp-probe/vpp"
)

func TestDotOutput(t *testing.T) {
	b, err := ioutil.ReadFile("/home/ondrej/probe-discover-cluster.json")
	if err != nil {
		t.Fatal(err)
	}

	instances := []*vpp.Instance{}
	if err := json.Unmarshal(b, &instances); err != nil {
		var terr *json.UnmarshalTypeError
		if errors.As(err, &terr) {
			t.Fatalf("%#v (%+v)", terr, terr)
		} else {
			t.Fatalf("unmarshal error: %v (%#v)", err, err)
		}
	}

	topo, err := Build(instances)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	PrintTopologyDot(&buf, instances, topo)

	fmt.Println(buf.String())
}
