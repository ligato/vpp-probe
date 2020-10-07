//  Copyright (c) 2020 Cisco and/or its affiliates.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at:
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

package vpptrace

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func init() {
	logrus.SetLevel(logrus.TraceLevel)
}

func TestParseTrace(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		want    []Packet
		wantErr bool
	}{
		{
			name: "",
			data: `------------------- Start of thread 0 vpp_main -------------------
Packet 1

00:00:00:209689: virtio-input
  virtio: hw_if_index 1 next-index 4 vring 0 len 42
    hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
00:00:00:209709: ethernet-input
  ARP: 02:fe:2e:5d:d6:9a -> ff:ff:ff:ff:ff:ff
00:00:00:209722: arp-input
  request, type ethernet/IP4, address size 6/4
  02:fe:2e:5d:d6:9a/192.168.33.10 -> 00:00:00:00:00:00/192.168.33.1
00:00:00:209739: arp-reply
  request, type ethernet/IP4, address size 6/4
  02:fe:2e:5d:d6:9a/192.168.33.10 -> 00:00:00:00:00:00/192.168.33.1
00:00:00:210050: tap0-output
  tap0 
  ARP: 02:fe:a0:10:fd:8b -> 02:fe:2e:5d:d6:9a
  reply, type ethernet/IP4, address size 6/4
  02:fe:a0:10:fd:8b/192.168.33.1 -> 02:fe:2e:5d:d6:9a/192.168.33.10

Packet 2

00:00:00:211596: virtio-input
  virtio: hw_if_index 1 next-index 4 vring 0 len 98
    hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
00:00:00:211601: ethernet-input
  IP4: 02:fe:2e:5d:d6:9a -> 02:fe:a0:10:fd:8b
00:00:00:211604: ip4-input
  ICMP: 192.168.33.10 -> 192.168.33.1
    tos 0x00, ttl 64, length 84, checksum 0x6d5f dscp CS0 ecn NON_ECN
    fragment id 0x09ee, flags DONT_FRAGMENT
  ICMP echo_request checksum 0x315
00:00:00:211608: ip4-lookup
  fib 0 dpo-idx 7 flow hash: 0x00000000
  ICMP: 192.168.33.10 -> 192.168.33.1
    tos 0x00, ttl 64, length 84, checksum 0x6d5f dscp CS0 ecn NON_ECN
    fragment id 0x09ee, flags DONT_FRAGMENT
  ICMP echo_request checksum 0x315
00:00:00:211614: ip4-local
    ICMP: 192.168.33.10 -> 192.168.33.1
      tos 0x00, ttl 64, length 84, checksum 0x6d5f dscp CS0 ecn NON_ECN
      fragment id 0x09ee, flags DONT_FRAGMENT
    ICMP echo_request checksum 0x315
00:00:00:211618: ip4-icmp-input
  ICMP: 192.168.33.10 -> 192.168.33.1
    tos 0x00, ttl 64, length 84, checksum 0x6d5f dscp CS0 ecn NON_ECN
    fragment id 0x09ee, flags DONT_FRAGMENT
  ICMP echo_request checksum 0x315
00:00:00:211620: ip4-icmp-echo-request
  ICMP: 192.168.33.10 -> 192.168.33.1
    tos 0x00, ttl 64, length 84, checksum 0x6d5f dscp CS0 ecn NON_ECN
    fragment id 0x09ee, flags DONT_FRAGMENT
  ICMP echo_request checksum 0x315
00:00:00:211633: ip4-load-balance
  fib 0 dpo-idx 1 flow hash: 0x00000000
  ICMP: 192.168.33.1 -> 192.168.33.10
    tos 0x00, ttl 64, length 84, checksum 0xe365 dscp CS0 ecn NON_ECN
    fragment id 0x93e7, flags DONT_FRAGMENT
  ICMP echo_reply checksum 0xb15
00:00:00:211636: ip4-rewrite
  tx_sw_if_index 1 dpo-idx 1 : ipv4 via 192.168.33.10 tap0: mtu:9000 next:3 02fe2e5dd69a02fea010fd8b0800 flow hash: 0x00000000
  00000000: 02fe2e5dd69a02fea010fd8b08004500005493e740004001e365c0a82101c0a8
  00000020: 210a00000b15001200016fce2a5f0000000092d70900000000001011
00:00:00:211639: tap0-output
  tap0 
  IP4: 02:fe:a0:10:fd:8b -> 02:fe:2e:5d:d6:9a
  ICMP: 192.168.33.1 -> 192.168.33.10
    tos 0x00, ttl 64, length 84, checksum 0xe365 dscp CS0 ecn NON_ECN
    fragment id 0x93e7, flags DONT_FRAGMENT
  ICMP echo_reply checksum 0xb15
`,
			want: []Packet{
				{
					ID: 1,
					Captures: []Capture{
						{
							Name:    "virtio-input",
							Start:   209689000,
							Content: "virtio: hw_if_index 1 next-index 4 vring 0 len 42\n  hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1\n"}, {
							Name:    "ethernet-input",
							Start:   209709000,
							Content: "ARP: 02:fe:2e:5d:d6:9a -> ff:ff:ff:ff:ff:ff\n"}, {
							Name:    "arp-input",
							Start:   209722000,
							Content: "request, type ethernet/IP4, address size 6/4\n02:fe:2e:5d:d6:9a/192.168.33.10 -> 00:00:00:00:00:00/192.168.33.1\n"}, {
							Name:    "arp-reply",
							Start:   209739000,
							Content: "request, type ethernet/IP4, address size 6/4\n02:fe:2e:5d:d6:9a/192.168.33.10 -> 00:00:00:00:00:00/192.168.33.1\n"}, {
							Name:    "tap0-output",
							Start:   210050000,
							Content: "tap0\nARP: 02:fe:a0:10:fd:8b -> 02:fe:2e:5d:d6:9a\nreply, type ethernet/IP4, address size 6/4\n02:fe:a0:10:fd:8b/192.168.33.1 -> 02:fe:2e:5d:d6:9a/192.168.33.10\n"},
					},
				}, {
					ID: 2,
					Captures: []Capture{
						{
							Name:    "virtio-input",
							Start:   211596000,
							Content: "virtio: hw_if_index 1 next-index 4 vring 0 len 98\n  hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1\n"}, {
							Name:    "ethernet-input",
							Start:   211601000,
							Content: "IP4: 02:fe:2e:5d:d6:9a -> 02:fe:a0:10:fd:8b\n"}, {
							Name:    "ip4-input",
							Start:   211604000,
							Content: "ICMP: 192.168.33.10 -> 192.168.33.1\n  tos 0x00, ttl 64, length 84, checksum 0x6d5f dscp CS0 ecn NON_ECN\n  fragment id 0x09ee, flags DONT_FRAGMENT\nICMP echo_request checksum 0x315\n"}, {
							Name:    "ip4-lookup",
							Start:   211608000,
							Content: "fib 0 dpo-idx 7 flow hash: 0x00000000\nICMP: 192.168.33.10 -> 192.168.33.1\n  tos 0x00, ttl 64, length 84, checksum 0x6d5f dscp CS0 ecn NON_ECN\n  fragment id 0x09ee, flags DONT_FRAGMENT\nICMP echo_request checksum 0x315\n"}, {
							Name:    "ip4-local",
							Start:   211614000,
							Content: "ICMP: 192.168.33.10 -> 192.168.33.1\n  tos 0x00, ttl 64, length 84, checksum 0x6d5f dscp CS0 ecn NON_ECN\n  fragment id 0x09ee, flags DONT_FRAGMENT\nICMP echo_request checksum 0x315\n"}, {
							Name:    "ip4-icmp-input",
							Start:   211618000,
							Content: "ICMP: 192.168.33.10 -> 192.168.33.1\n  tos 0x00, ttl 64, length 84, checksum 0x6d5f dscp CS0 ecn NON_ECN\n  fragment id 0x09ee, flags DONT_FRAGMENT\nICMP echo_request checksum 0x315\n"}, {
							Name:    "ip4-icmp-echo-request",
							Start:   211620000,
							Content: "ICMP: 192.168.33.10 -> 192.168.33.1\n  tos 0x00, ttl 64, length 84, checksum 0x6d5f dscp CS0 ecn NON_ECN\n  fragment id 0x09ee, flags DONT_FRAGMENT\nICMP echo_request checksum 0x315\n"}, {
							Name:    "ip4-load-balance",
							Start:   211633000,
							Content: "fib 0 dpo-idx 1 flow hash: 0x00000000\nICMP: 192.168.33.1 -> 192.168.33.10\n  tos 0x00, ttl 64, length 84, checksum 0xe365 dscp CS0 ecn NON_ECN\n  fragment id 0x93e7, flags DONT_FRAGMENT\nICMP echo_reply checksum 0xb15\n"}, {
							Name:    "ip4-rewrite",
							Start:   211636000,
							Content: "tx_sw_if_index 1 dpo-idx 1 : ipv4 via 192.168.33.10 tap0: mtu:9000 next:3 02fe2e5dd69a02fea010fd8b0800 flow hash: 0x00000000\n00000000: 02fe2e5dd69a02fea010fd8b08004500005493e740004001e365c0a82101c0a8\n00000020: 210a00000b15001200016fce2a5f0000000092d70900000000001011\n"}, {
							Name:    "tap0-output",
							Start:   211639000,
							Content: "tap0\nIP4: 02:fe:a0:10:fd:8b -> 02:fe:2e:5d:d6:9a\nICMP: 192.168.33.1 -> 192.168.33.10\n  tos 0x00, ttl 64, length 84, checksum 0xe365 dscp CS0 ecn NON_ECN\n  fragment id 0x93e7, flags DONT_FRAGMENT\nICMP echo_reply checksum 0xb15\n"},
					},
				},
			},
			wantErr: false,
		},
		{
			name:    "empty",
			data:    `No packets in trace buffer`,
			want:    []Packet{},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseTracePackets(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseResult() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != nil && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseResult() got:\n%#v\nwant:\n%#v", got, tt.want)
			}
		})
	}
}

func Test_parseTimestamp(t *testing.T) {
	tests := []struct {
		name    string
		str     string
		want    time.Duration
		wantErr bool
	}{
		{
			str:  "00:00:00:199298",
			want: time.Microsecond * 199298,
		},
		{
			str:  "00:00:05:000000",
			want: time.Second * 5,
		},
		{
			str:  "00:01:05:000000",
			want: time.Second * 65,
		},
		{
			str:  "03:00:00:000000",
			want: time.Hour * 3,
		},
		{
			str:  "01:02:03:000004",
			want: time.Hour + time.Minute*2 + time.Second*3 + time.Microsecond*4,
		},
		{
			name:    "not in microseconds",
			str:     "00:00:00:123",
			wantErr: true,
		},
		{
			name:    "missing microseconds",
			str:     "00:00:00",
			wantErr: true,
		},
		{
			name:    "invalid",
			str:     "0",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s(%v)", tt.name, tt.str), func(t *testing.T) {
			got, err := parseTimestamp(tt.str)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseTimestamp() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseTimestamp() got = %v, want %v", got, tt.want)
			}
		})
	}
}
