package vpp

import (
	"reflect"
	"testing"
	"time"

	"go.ligato.io/vpp-probe/probe"
)

func Test_parseUptime(t *testing.T) {
	type args struct {
		raw string
	}
	tests := []struct {
		name    string
		args    args
		want    time.Duration
		wantErr bool
	}{
		{
			name: "basic",
			args: args{
				raw: "Time now 3180.278756, Tue, 1 Dec 2020 11:52:45 GMT",
			},
			want:    3180278756 * time.Microsecond,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseUptime(tt.args.raw)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseUptime() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseUptime() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_parseClock(t *testing.T) {
	type args struct {
		raw string
	}
	tests := []struct {
		name    string
		args    args
		want    time.Time
		wantErr bool
	}{
		{
			name: "basic",
			args: args{
				raw: "Time now 3180.278756, Tue, 1 Dec 2020 11:52:45 GMT",
			},
			want:    toTime("Tue, 01 Dec 2020 11:52:45 GMT"),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseClock(tt.args.raw)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseClock() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseClock() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func toTime(str string) time.Time {
	t, err := time.Parse(time.RFC1123, str)
	if err != nil {
		panic(err)
	}
	return t
}

func TestShowClockCLI(t *testing.T) {
	type args struct {
		cli probe.CliExecutor
	}
	tests := []struct {
		name    string
		args    args
		want    *ClockData
		wantErr bool
	}{
		{
			name: "bare",
			args: args{
				NewMockCLI(map[string]string{
					"show clock": "Time now 164118.517287, Wed, 5 May 2021 15:39:11 GMT",
				}),
			},
			want: &ClockData{
				Uptime: "164118.517287",
				Clock:  "Wed, 5 May 2021 15:39:11 GMT",
			},
		},
		{
			name: "newline",
			args: args{
				NewMockCLI(map[string]string{
					"show clock": "Time now 164118.517287, Wed, 5 May 2021 15:39:11 GMT\r\n",
				}),
			},
			want: &ClockData{
				Uptime: "164118.517287",
				Clock:  "Wed, 5 May 2021 15:39:11 GMT",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ShowClockCLI(tt.args.cli)
			if (err != nil) != tt.wantErr {
				t.Errorf("ShowClockCLI() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ShowClockCLI() got = %v, want %v", got, tt.want)
			}
		})
	}
}

type MockCLI struct {
	replymap map[string]string
}

func NewMockCLI(replymap map[string]string) *MockCLI {
	return &MockCLI{
		replymap: replymap,
	}
}

func (m *MockCLI) RunCli(cmd string) (string, error) {
	return m.replymap[cmd], nil
}
