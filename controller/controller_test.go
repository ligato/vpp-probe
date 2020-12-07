package controller

import (
	"reflect"
	"testing"
)

func TestParseQueries(t *testing.T) {
	tests := []struct {
		name    string
		queries []string
		expect  []map[string]string
	}{
		// Generic
		{"simple query", []string{"key1=value1"}, []map[string]string{
			{"key1": "value1"},
		}},
		{"multiple params", []string{"key1=value1;key2=value2"}, []map[string]string{
			{"key1": "value1", "key2": "value2"},
		}},
		{"repeated param", []string{"key1=value1;key1=value2"}, []map[string]string{
			{"key1": "value2"},
		},
		// TODO: decide if this should be even valid (param value is being overwritten)
		},
		{"two queries", []string{"key1=value1", "key2=value2"}, []map[string]string{
			{"key1": "value1"},
			{"key2": "value2"},
		}},
		// Kube
		{"kube label selector", []string{"label=app=example"}, []map[string]string{
			{"label": "app=example"},
		}},
		{"kube multiple selectors", []string{"label=app=example,env=test"}, []map[string]string{
			{"label": "app=example,env=test"},
		}},
		{"kube set selector", []string{"label=app in (example, hello)"}, []map[string]string{
			{"label": "app in (example, hello)"},
		}},
		{"kube multiple params", []string{"label=app=example;namespace=my-system"}, []map[string]string{
			{"label": "app=example", "namespace": "my-system"},
		}},
		{"kube multiple queries", []string{"label=app=example", "label=app=hello"}, []map[string]string{
			{"label": "app=example"},
			{"label": "app=hello"},
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parsed := parseQueries(test.queries)

			if !reflect.DeepEqual(parsed, test.expect) {
				t.Errorf("for queries %q expected:\n%q\ngot:\n%q,", test.queries, test.expect, parsed)
			}
		})
	}
}
