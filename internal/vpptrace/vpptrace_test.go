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
	"io/ioutil"
	"reflect"
	"strings"
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
		want    *Traces
		wantErr bool
	}{
		{
			name: "",
			data: `------------------- Start of thread 0 vpp_main -------------------
Packet 1

02:04:10:806859: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c655 nsec 0x315d5496 vlan 0 vlan_tpid 0
02:04:10:806867: ethernet-input
  IP4: 02:42:ac:13:00:03 -> 02:42:ac:13:00:04
02:04:10:806873: ip4-input
  TCP: 172.19.0.3 -> 172.19.0.4
    tos 0x00, ttl 63, length 52, checksum 0x8464 dscp CS0 ecn NON_ECN
    fragment id 0x5f32, flags DONT_FRAGMENT
  TCP: 5001 -> 46792
    seq. 0xaab822d2 ack 0xd4a90fab
    flags 0x10 ACK, tcp header: 32 bytes
    window 508, checksum 0x0000
02:04:10:806878: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac030013ac 00010106b6c81389 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.3 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 5001 -> 46792 tcp flags (valid) 10 rsvd 0
02:04:10:806884: error-drop
  rx:host-eth0
02:04:10:806884: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 2

02:04:10:806859: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c655 nsec 0x315d9406 vlan 0 vlan_tpid 0
02:04:10:806867: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:ac:13:00:03
02:04:10:806877: error-drop
  rx:host-eth0
02:04:10:806882: drop
  ethernet-input: l3 mac mismatch

Packet 3

02:04:10:806859: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c655 nsec 0x315da25b vlan 0 vlan_tpid 0
02:04:10:806867: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:ac:13:00:03
02:04:10:806877: error-drop
  rx:host-eth0
02:04:10:806882: drop
  ethernet-input: l3 mac mismatch

Packet 4

02:04:10:806859: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c655 nsec 0x315e748a vlan 0 vlan_tpid 0
02:04:10:806867: ethernet-input
  IP4: 02:42:ac:13:00:03 -> 02:42:ac:13:00:04
02:04:10:806873: ip4-input
  TCP: 172.19.0.3 -> 172.19.0.4
    tos 0x00, ttl 63, length 52, checksum 0x8463 dscp CS0 ecn NON_ECN
    fragment id 0x5f33, flags DONT_FRAGMENT
  TCP: 5001 -> 46792
    seq. 0xaab822d3 ack 0xd4a90fab
    flags 0x10 ACK, tcp header: 32 bytes
    window 508, checksum 0x0000
02:04:10:806878: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac030013ac 00010106b6c81389 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.3 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 5001 -> 46792 tcp flags (valid) 10 rsvd 0
02:04:10:806884: error-drop
  rx:host-eth0
02:04:10:806884: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 5

02:04:10:808200: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c655 nsec 0x31736723 vlan 0 vlan_tpid 0
02:04:10:808210: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:10:808218: error-drop
  rx:host-eth0
02:04:10:808226: drop
  ethernet-input: l3 mac mismatch

Packet 6

02:04:10:808200: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c655 nsec 0x3173b502 vlan 0 vlan_tpid 0
02:04:10:808210: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:10:808221: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x265e dscp CS0 ecn NON_ECN
    fragment id 0xbc3a, flags DONT_FRAGMENT
  TCP: 34344 -> 6443
    seq. 0x38186a3e ack 0x31e19cb6
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:10:808228: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8628 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34344 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:10:808233: error-drop
  rx:host-eth0
02:04:10:808233: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 7

02:04:10:808200: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c655 nsec 0x317a2f39 vlan 0 vlan_tpid 0
02:04:10:808210: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:10:808218: error-drop
  rx:host-eth0
02:04:10:808226: drop
  ethernet-input: l3 mac mismatch

Packet 8

02:04:10:808200: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c655 nsec 0x317a7211 vlan 0 vlan_tpid 0
02:04:10:808210: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:10:808221: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x265d dscp CS0 ecn NON_ECN
    fragment id 0xbc3b, flags DONT_FRAGMENT
  TCP: 34344 -> 6443
    seq. 0x38186a3e ack 0x31e19cd0
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:10:808228: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8628 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34344 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:10:808233: error-drop
  rx:host-eth0
02:04:10:808233: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 9

02:04:10:809447: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c655 nsec 0x318330ee vlan 0 vlan_tpid 0
02:04:10:809457: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:10:809463: error-drop
  rx:host-eth0
02:04:10:809472: drop
  ethernet-input: l3 mac mismatch

Packet 10

02:04:10:809447: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c655 nsec 0x3183f2c0 vlan 0 vlan_tpid 0
02:04:10:809457: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:10:809468: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xcb59 dscp CS0 ecn NON_ECN
    fragment id 0x173f, flags DONT_FRAGMENT
  TCP: 34348 -> 6443
    seq. 0x9b353e92 ack 0xcbb5eb14
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:10:809474: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b862c 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34348 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:10:809479: error-drop
  rx:host-eth0
02:04:10:809479: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 11

02:04:10:809447: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c655 nsec 0x3187f050 vlan 0 vlan_tpid 0
02:04:10:809457: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:10:809463: error-drop
  rx:host-eth0
02:04:10:809472: drop
  ethernet-input: l3 mac mismatch

Packet 12

02:04:10:809447: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c655 nsec 0x3188788d vlan 0 vlan_tpid 0
02:04:10:809457: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:10:809468: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xcb58 dscp CS0 ecn NON_ECN
    fragment id 0x1740, flags DONT_FRAGMENT
  TCP: 34348 -> 6443
    seq. 0x9b353e92 ack 0xcbb5eb2e
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:10:809474: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b862c 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34348 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:10:809479: error-drop
  rx:host-eth0
02:04:10:809479: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 13

02:04:10:810721: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 130 snaplen 130 mac 66 net 80
      sec 0x5f35c655 nsec 0x31933beb vlan 0 vlan_tpid 0
02:04:10:810861: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:10:810868: error-drop
  rx:host-eth0
02:04:10:810875: drop
  ethernet-input: l3 mac mismatch

Packet 14

02:04:10:810721: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c655 nsec 0x31937ef5 vlan 0 vlan_tpid 0
02:04:10:810861: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:10:810871: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x265c dscp CS0 ecn NON_ECN
    fragment id 0xbc3c, flags DONT_FRAGMENT
  TCP: 34344 -> 6443
    seq. 0x38186a3e ack 0x31e19d10
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:10:810877: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8628 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34344 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:10:810883: error-drop
  rx:host-eth0
02:04:10:810884: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 15

02:04:10:810721: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 120 snaplen 120 mac 66 net 80
      sec 0x5f35c655 nsec 0x3193f648 vlan 0 vlan_tpid 0
02:04:10:810861: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:10:810868: error-drop
  rx:host-eth0
02:04:10:810875: drop
  ethernet-input: l3 mac mismatch

Packet 16

02:04:10:810721: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c655 nsec 0x31940e4f vlan 0 vlan_tpid 0
02:04:10:810861: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:10:810871: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x265b dscp CS0 ecn NON_ECN
    fragment id 0xbc3d, flags DONT_FRAGMENT
  TCP: 34344 -> 6443
    seq. 0x38186a3e ack 0x31e19d46
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:10:810877: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8628 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34344 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:10:810883: error-drop
  rx:host-eth0
02:04:10:810884: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 17

02:04:10:810721: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 104 snaplen 104 mac 66 net 80
      sec 0x5f35c655 nsec 0x31943071 vlan 0 vlan_tpid 0
02:04:10:810861: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:10:810868: error-drop
  rx:host-eth0
02:04:10:810875: drop
  ethernet-input: l3 mac mismatch

Packet 18

02:04:10:810721: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c655 nsec 0x3194800b vlan 0 vlan_tpid 0
02:04:10:810861: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:10:810871: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x265a dscp CS0 ecn NON_ECN
    fragment id 0xbc3e, flags DONT_FRAGMENT
  TCP: 34344 -> 6443
    seq. 0x38186a3e ack 0x31e19d6c
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:10:810877: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8628 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34344 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:10:810883: error-drop
  rx:host-eth0
02:04:10:810884: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 19

02:04:10:810721: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c655 nsec 0x31979260 vlan 0 vlan_tpid 0
02:04:10:810861: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:10:810868: error-drop
  rx:host-eth0
02:04:10:810875: drop
  ethernet-input: l3 mac mismatch

Packet 20

02:04:10:810721: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c655 nsec 0x319a6638 vlan 0 vlan_tpid 0
02:04:10:810861: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:10:810871: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x2659 dscp CS0 ecn NON_ECN
    fragment id 0xbc3f, flags DONT_FRAGMENT
  TCP: 34344 -> 6443
    seq. 0x38186a3e ack 0x31e19d84
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:10:810877: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8628 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34344 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:10:810883: error-drop
  rx:host-eth0
02:04:10:810884: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 21

02:04:10:810721: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c655 nsec 0x319b1a62 vlan 0 vlan_tpid 0
02:04:10:810861: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:10:810868: error-drop
  rx:host-eth0
02:04:10:810875: drop
  ethernet-input: l3 mac mismatch

Packet 22

02:04:10:810721: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 96 snaplen 96 mac 66 net 80
      sec 0x5f35c655 nsec 0x31a1c7dd vlan 0 vlan_tpid 0
02:04:10:810861: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:10:810868: error-drop
  rx:host-eth0
02:04:10:810875: drop
  ethernet-input: l3 mac mismatch

Packet 23

02:04:10:810721: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 134 snaplen 134 mac 66 net 80
      sec 0x5f35c655 nsec 0x31a24c53 vlan 0 vlan_tpid 0
02:04:10:810861: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:10:810868: error-drop
  rx:host-eth0
02:04:10:810875: drop
  ethernet-input: l3 mac mismatch

Packet 24

02:04:10:810721: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c655 nsec 0x31a2537b vlan 0 vlan_tpid 0
02:04:10:810861: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:10:810871: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xcb57 dscp CS0 ecn NON_ECN
    fragment id 0x1741, flags DONT_FRAGMENT
  TCP: 34348 -> 6443
    seq. 0x9b353e92 ack 0xcbb5eb4c
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:10:810877: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b862c 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34348 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:10:810883: error-drop
  rx:host-eth0
02:04:10:810884: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 25

02:04:10:810721: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 96 snaplen 96 mac 66 net 80
      sec 0x5f35c655 nsec 0x31a27cfa vlan 0 vlan_tpid 0
02:04:10:810861: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:10:810868: error-drop
  rx:host-eth0
02:04:10:810875: drop
  ethernet-input: l3 mac mismatch

Packet 26

02:04:10:810721: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c655 nsec 0x31a2c67b vlan 0 vlan_tpid 0
02:04:10:810861: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:10:810871: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xcb56 dscp CS0 ecn NON_ECN
    fragment id 0x1742, flags DONT_FRAGMENT
  TCP: 34348 -> 6443
    seq. 0x9b353e92 ack 0xcbb5ebae
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:10:810877: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b862c 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34348 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:10:810883: error-drop
  rx:host-eth0
02:04:10:810884: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 27

02:04:10:810721: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 100 snaplen 100 mac 66 net 80
      sec 0x5f35c655 nsec 0x31a2c8ca vlan 0 vlan_tpid 0
02:04:10:810861: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:10:810868: error-drop
  rx:host-eth0
02:04:10:810875: drop
  ethernet-input: l3 mac mismatch

Packet 28

02:04:10:810721: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c655 nsec 0x31a30326 vlan 0 vlan_tpid 0
02:04:10:810861: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:10:810868: error-drop
  rx:host-eth0
02:04:10:810875: drop
  ethernet-input: l3 mac mismatch

Packet 29

02:04:10:810721: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c655 nsec 0x31a30d5f vlan 0 vlan_tpid 0
02:04:10:810861: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:10:810871: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xcb55 dscp CS0 ecn NON_ECN
    fragment id 0x1743, flags DONT_FRAGMENT
  TCP: 34348 -> 6443
    seq. 0x9b353e92 ack 0xcbb5ebd0
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:10:810877: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b862c 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34348 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:10:810883: error-drop
  rx:host-eth0
02:04:10:810884: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 30

02:04:10:810721: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 96 snaplen 96 mac 66 net 80
      sec 0x5f35c655 nsec 0x31a35050 vlan 0 vlan_tpid 0
02:04:10:810861: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:10:810868: error-drop
  rx:host-eth0
02:04:10:810875: drop
  ethernet-input: l3 mac mismatch

Packet 31

02:04:10:810721: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c655 nsec 0x31a355cb vlan 0 vlan_tpid 0
02:04:10:810861: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:10:810871: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xcb54 dscp CS0 ecn NON_ECN
    fragment id 0x1744, flags DONT_FRAGMENT
  TCP: 34348 -> 6443
    seq. 0x9b353e92 ack 0xcbb5ebea
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:10:810877: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b862c 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34348 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:10:810883: error-drop
  rx:host-eth0
02:04:10:810884: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 32

02:04:10:810721: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c655 nsec 0x31a38e42 vlan 0 vlan_tpid 0
02:04:10:810861: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:10:810871: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xcb53 dscp CS0 ecn NON_ECN
    fragment id 0x1745, flags DONT_FRAGMENT
  TCP: 34348 -> 6443
    seq. 0x9b353e92 ack 0xcbb5ec08
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:10:810877: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b862c 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34348 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:10:810883: error-drop
  rx:host-eth0
02:04:10:810884: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 33

02:04:10:811946: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c655 nsec 0x31a6d9f8 vlan 0 vlan_tpid 0
02:04:10:811950: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:10:811953: error-drop
  rx:host-eth0
02:04:10:811957: drop
  ethernet-input: l3 mac mismatch

Packet 34

02:04:10:811946: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c655 nsec 0x31a74466 vlan 0 vlan_tpid 0
02:04:10:811950: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:10:811955: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xcb52 dscp CS0 ecn NON_ECN
    fragment id 0x1746, flags DONT_FRAGMENT
  TCP: 34348 -> 6443
    seq. 0x9b353e92 ack 0xcbb5ec22
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:10:811958: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b862c 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34348 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:10:811961: error-drop
  rx:host-eth0
02:04:10:811961: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 35

02:04:10:811946: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c655 nsec 0x31a80787 vlan 0 vlan_tpid 0
02:04:10:811950: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:10:811953: error-drop
  rx:host-eth0
02:04:10:811957: drop
  ethernet-input: l3 mac mismatch

Packet 36

02:04:10:811946: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c655 nsec 0x31a85394 vlan 0 vlan_tpid 0
02:04:10:811950: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:10:811955: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xcb51 dscp CS0 ecn NON_ECN
    fragment id 0x1747, flags DONT_FRAGMENT
  TCP: 34348 -> 6443
    seq. 0x9b353e92 ack 0xcbb5ec3a
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:10:811958: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b862c 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34348 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:10:811961: error-drop
  rx:host-eth0
02:04:10:811961: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 37

02:04:10:811946: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c655 nsec 0x31a92e19 vlan 0 vlan_tpid 0
02:04:10:811950: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:10:811953: error-drop
  rx:host-eth0
02:04:10:811957: drop
  ethernet-input: l3 mac mismatch

Packet 38

02:04:10:850537: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c655 nsec 0x33fa9700 vlan 0 vlan_tpid 0
02:04:10:850547: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:10:850554: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xe7e9 dscp CS0 ecn NON_ECN
    fragment id 0xfaae, flags DONT_FRAGMENT
  TCP: 34350 -> 6443
    seq. 0x40a6e94d ack 0xb1f63ac6
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:10:850558: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b862e 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34350 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:10:850564: error-drop
  rx:host-eth0
02:04:10:850566: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 39

02:04:10:859134: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c655 nsec 0x3474a7bc vlan 0 vlan_tpid 0
02:04:10:859140: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:10:859144: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xcb50 dscp CS0 ecn NON_ECN
    fragment id 0x1748, flags DONT_FRAGMENT
  TCP: 34348 -> 6443
    seq. 0x9b353e92 ack 0xcbb5ec3b
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:10:859148: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b862c 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34348 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:10:859154: error-drop
  rx:host-eth0
02:04:10:859155: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 40

02:04:10:859134: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c655 nsec 0x3474b93c vlan 0 vlan_tpid 0
02:04:10:859140: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:10:859144: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x2658 dscp CS0 ecn NON_ECN
    fragment id 0xbc40, flags DONT_FRAGMENT
  TCP: 34344 -> 6443
    seq. 0x38186a3e ack 0x31e19d85
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:10:859148: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8628 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34344 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:10:859154: error-drop
  rx:host-eth0
02:04:10:859155: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 41

02:04:10:863347: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 74 snaplen 74 mac 66 net 80
      sec 0x5f35c655 nsec 0x34b7ea55 vlan 0 vlan_tpid 0
02:04:10:863355: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:10:863361: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 60, checksum 0xbfc4 dscp CS0 ecn NON_ECN
    fragment id 0x22cc, flags DONT_FRAGMENT
  TCP: 34382 -> 6443
    seq. 0x77709927 ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 64240, checksum 0x0000
02:04:10:863367: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b864e 0302ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34382 -> 6443 tcp flags (valid) 02 rsvd 0
02:04:10:863374: error-drop
  rx:host-eth0
02:04:10:863374: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 42

02:04:10:863347: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 74 snaplen 74 mac 66 net 80
      sec 0x5f35c655 nsec 0x34b853b7 vlan 0 vlan_tpid 0
02:04:10:863355: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:10:863365: error-drop
  rx:host-eth0
02:04:10:863372: drop
  ethernet-input: l3 mac mismatch

Packet 43

02:04:10:863347: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c655 nsec 0x34b88e67 vlan 0 vlan_tpid 0
02:04:10:863355: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:10:863361: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xbfcb dscp CS0 ecn NON_ECN
    fragment id 0x22cd, flags DONT_FRAGMENT
  TCP: 34382 -> 6443
    seq. 0x77709928 ack 0x9c416743
    flags 0x10 ACK, tcp header: 32 bytes
    window 502, checksum 0x0000
02:04:10:863367: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b864e 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34382 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:10:863374: error-drop
  rx:host-eth0
02:04:10:863374: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 44

02:04:10:909797: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 74 snaplen 74 mac 66 net 80
      sec 0x5f35c655 nsec 0x377ab790 vlan 0 vlan_tpid 0
02:04:10:909817: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:10:909836: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 60, checksum 0x8c3a dscp CS0 ecn NON_ECN
    fragment id 0x5656, flags DONT_FRAGMENT
  TCP: 34394 -> 6443
    seq. 0x737cff7f ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 64240, checksum 0x0000
02:04:10:909857: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b865a 0302ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34394 -> 6443 tcp flags (valid) 02 rsvd 0
02:04:10:909867: error-drop
  rx:host-eth0
02:04:10:909868: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 45

02:04:10:909797: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 74 snaplen 74 mac 66 net 80
      sec 0x5f35c655 nsec 0x377ac01f vlan 0 vlan_tpid 0
02:04:10:909817: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:10:909836: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 60, checksum 0x87e5 dscp CS0 ecn NON_ECN
    fragment id 0x5aab, flags DONT_FRAGMENT
  TCP: 34392 -> 6443
    seq. 0xfdf35cb3 ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 64240, checksum 0x0000
02:04:10:909857: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8658 0302ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34392 -> 6443 tcp flags (valid) 02 rsvd 0
02:04:10:909867: error-drop
  rx:host-eth0
02:04:10:909868: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 46

02:04:10:909797: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 74 snaplen 74 mac 66 net 80
      sec 0x5f35c655 nsec 0x377babe2 vlan 0 vlan_tpid 0
02:04:10:909817: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:10:909831: error-drop
  rx:host-eth0
02:04:10:909843: drop
  ethernet-input: l3 mac mismatch

Packet 47

02:04:10:909797: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 74 snaplen 74 mac 66 net 80
      sec 0x5f35c655 nsec 0x377bac04 vlan 0 vlan_tpid 0
02:04:10:909817: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:10:909831: error-drop
  rx:host-eth0
02:04:10:909843: drop
  ethernet-input: l3 mac mismatch

Packet 48

02:04:10:909797: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c655 nsec 0x377c488c vlan 0 vlan_tpid 0
02:04:10:909817: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:10:909836: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x8c41 dscp CS0 ecn NON_ECN
    fragment id 0x5657, flags DONT_FRAGMENT
  TCP: 34394 -> 6443
    seq. 0x737cff80 ack 0x8f0a2adc
    flags 0x10 ACK, tcp header: 32 bytes
    window 502, checksum 0x0000
02:04:10:909857: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b865a 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34394 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:10:909867: error-drop
  rx:host-eth0
02:04:10:909868: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 49

02:04:10:909797: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c655 nsec 0x377c560a vlan 0 vlan_tpid 0
02:04:10:909817: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:10:909836: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x87ec dscp CS0 ecn NON_ECN
    fragment id 0x5aac, flags DONT_FRAGMENT
  TCP: 34392 -> 6443
    seq. 0xfdf35cb4 ack 0xc7e97322
    flags 0x10 ACK, tcp header: 32 bytes
    window 502, checksum 0x0000
02:04:10:909857: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8658 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34392 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:10:909867: error-drop
  rx:host-eth0
02:04:10:909868: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 50

02:04:10:909797: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c655 nsec 0x377f5df6 vlan 0 vlan_tpid 0
02:04:10:909817: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:10:909836: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 76, checksum 0xcb37 dscp CS0 ecn NON_ECN
    fragment id 0x1749, flags DONT_FRAGMENT
  TCP: 34348 -> 6443
    seq. 0x9b353e92 ack 0xcbb5ec3b
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:10:909857: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b862c 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34348 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:10:909867: error-drop
  rx:host-eth0
02:04:10:909868: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 51

02:04:10:909797: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000001 len 54 snaplen 54 mac 66 net 80
      sec 0x5f35c655 nsec 0x377fcec9 vlan 0 vlan_tpid 0
02:04:10:909817: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:10:909831: error-drop
  rx:host-eth0
02:04:10:909843: drop
  ethernet-input: l3 mac mismatch

Packet 52

02:04:10:933532: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 305 snaplen 305 mac 66 net 80
      sec 0x5f35c655 nsec 0x38d2e599 vlan 0 vlan_tpid 0
02:04:10:933542: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:10:933549: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 291, checksum 0xbedb dscp CS0 ecn NON_ECN
    fragment id 0x22ce, flags DONT_FRAGMENT
  TCP: 34382 -> 6443
    seq. 0x77709928 ack 0x9c416743
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 502, checksum 0x0000
02:04:10:933555: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b864e 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34382 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:10:933563: error-drop
  rx:host-eth0
02:04:10:933563: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 53

02:04:10:933532: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c655 nsec 0x38d343b9 vlan 0 vlan_tpid 0
02:04:10:933542: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:10:933553: error-drop
  rx:host-eth0
02:04:10:933561: drop
  ethernet-input: l3 mac mismatch

Packet 54

02:04:10:933532: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 1647 snaplen 1647 mac 66 net 80
      sec 0x5f35c655 nsec 0x38f21454 vlan 0 vlan_tpid 0
02:04:10:933542: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:10:933553: error-drop
  rx:host-eth0
02:04:10:933561: drop
  ethernet-input: l3 mac mismatch

Packet 55

02:04:10:933532: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c655 nsec 0x38f25942 vlan 0 vlan_tpid 0
02:04:10:933542: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:10:933549: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xbfc9 dscp CS0 ecn NON_ECN
    fragment id 0x22cf, flags DONT_FRAGMENT
  TCP: 34382 -> 6443
    seq. 0x77709a17 ack 0x9c416d70
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:10:933555: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b864e 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34382 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:10:933563: error-drop
  rx:host-eth0
02:04:10:933563: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 56

02:04:10:985880: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 305 snaplen 305 mac 66 net 80
      sec 0x5f35c656 nsec 0x71cefd vlan 0 vlan_tpid 0
02:04:10:985891: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:10:985901: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 291, checksum 0x8b51 dscp CS0 ecn NON_ECN
    fragment id 0x5658, flags DONT_FRAGMENT
  TCP: 34394 -> 6443
    seq. 0x737cff80 ack 0x8f0a2adc
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 502, checksum 0x0000
02:04:10:985906: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b865a 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34394 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:10:985912: error-drop
  rx:host-eth0
02:04:10:985912: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 57

02:04:10:985880: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x722b0e vlan 0 vlan_tpid 0
02:04:10:985891: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:10:985898: error-drop
  rx:host-eth0
02:04:10:985904: drop
  ethernet-input: l3 mac mismatch

Packet 58

02:04:10:985880: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 305 snaplen 305 mac 66 net 80
      sec 0x5f35c656 nsec 0x72c296 vlan 0 vlan_tpid 0
02:04:10:985891: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:10:985901: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 291, checksum 0x86fc dscp CS0 ecn NON_ECN
    fragment id 0x5aad, flags DONT_FRAGMENT
  TCP: 34392 -> 6443
    seq. 0xfdf35cb4 ack 0xc7e97322
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 502, checksum 0x0000
02:04:10:985906: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8658 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34392 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:10:985912: error-drop
  rx:host-eth0
02:04:10:985912: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 59

02:04:10:985880: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x72ec12 vlan 0 vlan_tpid 0
02:04:10:985891: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:10:985898: error-drop
  rx:host-eth0
02:04:10:985904: drop
  ethernet-input: l3 mac mismatch

Packet 60

02:04:10:989140: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 1647 snaplen 1647 mac 66 net 80
      sec 0x5f35c656 nsec 0xa6eb01 vlan 0 vlan_tpid 0
02:04:10:989147: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:10:989151: error-drop
  rx:host-eth0
02:04:10:989155: drop
  ethernet-input: l3 mac mismatch

Packet 61

02:04:10:989140: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0xa750cc vlan 0 vlan_tpid 0
02:04:10:989147: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:10:989153: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x8c3f dscp CS0 ecn NON_ECN
    fragment id 0x5659, flags DONT_FRAGMENT
  TCP: 34394 -> 6443
    seq. 0x737d006f ack 0x8f0a3109
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:10:989157: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b865a 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34394 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:10:989161: error-drop
  rx:host-eth0
02:04:10:989162: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 62

02:04:10:990235: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 1647 snaplen 1647 mac 66 net 80
      sec 0x5f35c656 nsec 0xabf2d9 vlan 0 vlan_tpid 0
02:04:10:990241: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:10:990244: error-drop
  rx:host-eth0
02:04:10:990248: drop
  ethernet-input: l3 mac mismatch

Packet 63

02:04:10:990235: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0xac20c2 vlan 0 vlan_tpid 0
02:04:10:990241: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:10:990246: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x87ea dscp CS0 ecn NON_ECN
    fragment id 0x5aae, flags DONT_FRAGMENT
  TCP: 34392 -> 6443
    seq. 0xfdf35da3 ack 0xc7e9794f
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:10:990249: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8658 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34392 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:10:990252: error-drop
  rx:host-eth0
02:04:10:990252: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 64

02:04:11:010913: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 1718 snaplen 1718 mac 66 net 80
      sec 0x5f35c656 nsec 0x1e4a5d8 vlan 0 vlan_tpid 0
02:04:11:010923: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:010931: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 1704, checksum 0xb954 dscp CS0 ecn NON_ECN
    fragment id 0x22d0, flags DONT_FRAGMENT
  TCP: 34382 -> 6443
    seq. 0x77709a17 ack 0x9c416d70
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:010938: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b864e 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34382 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:11:010946: error-drop
  rx:host-eth0
02:04:11:010946: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 65

02:04:11:010913: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x1e5143d vlan 0 vlan_tpid 0
02:04:11:010923: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:010936: error-drop
  rx:host-eth0
02:04:11:010943: drop
  ethernet-input: l3 mac mismatch

Packet 66

02:04:11:024500: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 247 snaplen 247 mac 66 net 80
      sec 0x5f35c656 nsec 0x2beb243 vlan 0 vlan_tpid 0
02:04:11:024509: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:024515: error-drop
  rx:host-eth0
02:04:11:024520: drop
  ethernet-input: l3 mac mismatch

Packet 67

02:04:11:024500: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x2bf114d vlan 0 vlan_tpid 0
02:04:11:024509: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:024517: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xbfc6 dscp CS0 ecn NON_ECN
    fragment id 0x22d2, flags DONT_FRAGMENT
  TCP: 34382 -> 6443
    seq. 0x7770a08b ack 0x9c416e25
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:024521: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b864e 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34382 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:024526: error-drop
  rx:host-eth0
02:04:11:024527: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 68

02:04:11:070655: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 1718 snaplen 1718 mac 66 net 80
      sec 0x5f35c656 nsec 0x567d84f vlan 0 vlan_tpid 0
02:04:11:070671: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:070688: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 1704, checksum 0x85ca dscp CS0 ecn NON_ECN
    fragment id 0x565a, flags DONT_FRAGMENT
  TCP: 34394 -> 6443
    seq. 0x737d006f ack 0x8f0a3109
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:070697: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b865a 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34394 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:11:070705: error-drop
  rx:host-eth0
02:04:11:070706: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 69

02:04:11:070655: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x5685c3d vlan 0 vlan_tpid 0
02:04:11:070671: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:070684: error-drop
  rx:host-eth0
02:04:11:070694: drop
  ethernet-input: l3 mac mismatch

Packet 70

02:04:11:070655: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 1713 snaplen 1713 mac 66 net 80
      sec 0x5f35c656 nsec 0x569458e vlan 0 vlan_tpid 0
02:04:11:070671: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:070688: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 1699, checksum 0x817a dscp CS0 ecn NON_ECN
    fragment id 0x5aaf, flags DONT_FRAGMENT
  TCP: 34392 -> 6443
    seq. 0xfdf35da3 ack 0xc7e9794f
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:070697: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8658 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34392 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:11:070705: error-drop
  rx:host-eth0
02:04:11:070706: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 71

02:04:11:070655: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x5698c52 vlan 0 vlan_tpid 0
02:04:11:070671: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:070684: error-drop
  rx:host-eth0
02:04:11:070694: drop
  ethernet-input: l3 mac mismatch

Packet 72

02:04:11:086988: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 166 snaplen 166 mac 66 net 80
      sec 0x5f35c656 nsec 0x64572b2 vlan 0 vlan_tpid 0
02:04:11:086996: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:087001: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 152, checksum 0xbf61 dscp CS0 ecn NON_ECN
    fragment id 0x22d3, flags DONT_FRAGMENT
  TCP: 34382 -> 6443
    seq. 0x7770a08b ack 0x9c416e25
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:087006: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b864e 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34382 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:11:087013: error-drop
  rx:host-eth0
02:04:11:087013: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 73

02:04:11:086988: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x6459942 vlan 0 vlan_tpid 0
02:04:11:086996: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:087005: error-drop
  rx:host-eth0
02:04:11:087011: drop
  ethernet-input: l3 mac mismatch

Packet 74

02:04:11:088742: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 191 snaplen 191 mac 66 net 80
      sec 0x5f35c656 nsec 0x67f5f25 vlan 0 vlan_tpid 0
02:04:11:088754: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:088760: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 177, checksum 0xbf47 dscp CS0 ecn NON_ECN
    fragment id 0x22d4, flags DONT_FRAGMENT
  TCP: 34382 -> 6443
    seq. 0x7770a0ef ack 0x9c416e25
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:088766: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b864e 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34382 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:11:088773: error-drop
  rx:host-eth0
02:04:11:088773: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 75

02:04:11:088742: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x67f89d3 vlan 0 vlan_tpid 0
02:04:11:088754: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:088764: error-drop
  rx:host-eth0
02:04:11:088771: drop
  ethernet-input: l3 mac mismatch

Packet 76

02:04:11:088742: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c656 nsec 0x68907c4 vlan 0 vlan_tpid 0
02:04:11:088754: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:088764: error-drop
  rx:host-eth0
02:04:11:088771: drop
  ethernet-input: l3 mac mismatch

Packet 77

02:04:11:088742: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x6894ec4 vlan 0 vlan_tpid 0
02:04:11:088754: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:088760: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xbfc3 dscp CS0 ecn NON_ECN
    fragment id 0x22d5, flags DONT_FRAGMENT
  TCP: 34382 -> 6443
    seq. 0x7770a16c ack 0x9c416e3d
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:088766: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b864e 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34382 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:088773: error-drop
  rx:host-eth0
02:04:11:088773: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 78

02:04:11:088742: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c656 nsec 0x689dfc5 vlan 0 vlan_tpid 0
02:04:11:088754: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:088764: error-drop
  rx:host-eth0
02:04:11:088771: drop
  ethernet-input: l3 mac mismatch

Packet 79

02:04:11:088742: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x689f853 vlan 0 vlan_tpid 0
02:04:11:088754: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:088760: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xbfc2 dscp CS0 ecn NON_ECN
    fragment id 0x22d6, flags DONT_FRAGMENT
  TCP: 34382 -> 6443
    seq. 0x7770a16c ack 0x9c416e55
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:088766: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b864e 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34382 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:088773: error-drop
  rx:host-eth0
02:04:11:088773: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 80

02:04:11:089902: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 112 snaplen 112 mac 66 net 80
      sec 0x5f35c656 nsec 0x696ec47 vlan 0 vlan_tpid 0
02:04:11:089912: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:089922: error-drop
  rx:host-eth0
02:04:11:089927: drop
  ethernet-input: l3 mac mismatch

Packet 81

02:04:11:089902: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x69721c3 vlan 0 vlan_tpid 0
02:04:11:089912: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:089924: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xbfc1 dscp CS0 ecn NON_ECN
    fragment id 0x22d7, flags DONT_FRAGMENT
  TCP: 34382 -> 6443
    seq. 0x7770a16c ack 0x9c416e83
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:089929: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b864e 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34382 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:089934: error-drop
  rx:host-eth0
02:04:11:089934: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 82

02:04:11:091004: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 247 snaplen 247 mac 66 net 80
      sec 0x5f35c656 nsec 0x6b0503e vlan 0 vlan_tpid 0
02:04:11:091012: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:091017: error-drop
  rx:host-eth0
02:04:11:091023: drop
  ethernet-input: l3 mac mismatch

Packet 83

02:04:11:091004: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x6b0c5fd vlan 0 vlan_tpid 0
02:04:11:091012: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:091019: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x87e7 dscp CS0 ecn NON_ECN
    fragment id 0x5ab1, flags DONT_FRAGMENT
  TCP: 34392 -> 6443
    seq. 0xfdf36412 ack 0xc7e97a04
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:091024: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8658 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34392 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:091029: error-drop
  rx:host-eth0
02:04:11:091030: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 84

02:04:11:093163: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 247 snaplen 247 mac 66 net 80
      sec 0x5f35c656 nsec 0x6ccb2da vlan 0 vlan_tpid 0
02:04:11:093171: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:093176: error-drop
  rx:host-eth0
02:04:11:093180: drop
  ethernet-input: l3 mac mismatch

Packet 85

02:04:11:093163: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x6cd1c69 vlan 0 vlan_tpid 0
02:04:11:093171: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:093178: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x8c3c dscp CS0 ecn NON_ECN
    fragment id 0x565c, flags DONT_FRAGMENT
  TCP: 34394 -> 6443
    seq. 0x737d06e3 ack 0x8f0a31be
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:093183: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b865a 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34394 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:093186: error-drop
  rx:host-eth0
02:04:11:093186: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 86

02:04:11:149824: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 275 snaplen 275 mac 66 net 80
      sec 0x5f35c656 nsec 0xa29748f vlan 0 vlan_tpid 0
02:04:11:149835: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:149842: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 261, checksum 0xbeef dscp CS0 ecn NON_ECN
    fragment id 0x22d8, flags DONT_FRAGMENT
  TCP: 34382 -> 6443
    seq. 0x7770a16c ack 0x9c416e83
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:149931: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b864e 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34382 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:11:149939: error-drop
  rx:host-eth0
02:04:11:149940: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 87

02:04:11:149824: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 291 snaplen 291 mac 66 net 80
      sec 0x5f35c656 nsec 0xa2a0433 vlan 0 vlan_tpid 0
02:04:11:149835: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:149842: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 277, checksum 0x8705 dscp CS0 ecn NON_ECN
    fragment id 0x5ab2, flags DONT_FRAGMENT
  TCP: 34392 -> 6443
    seq. 0xfdf36412 ack 0xc7e97a04
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:149931: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8658 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34392 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:11:149939: error-drop
  rx:host-eth0
02:04:11:149940: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 88

02:04:11:149824: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0xa2a2337 vlan 0 vlan_tpid 0
02:04:11:149835: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:149929: error-drop
  rx:host-eth0
02:04:11:149937: drop
  ethernet-input: l3 mac mismatch

Packet 89

02:04:11:153198: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 96 snaplen 96 mac 66 net 80
      sec 0x5f35c656 nsec 0xa3c17b0 vlan 0 vlan_tpid 0
02:04:11:153209: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:153222: error-drop
  rx:host-eth0
02:04:11:153232: drop
  ethernet-input: l3 mac mismatch

Packet 90

02:04:11:153198: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0xa3c766c vlan 0 vlan_tpid 0
02:04:11:153209: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:153217: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x87e5 dscp CS0 ecn NON_ECN
    fragment id 0x5ab3, flags DONT_FRAGMENT
  TCP: 34392 -> 6443
    seq. 0xfdf364f3 ack 0xc7e97a22
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:153225: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8658 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34392 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:153234: error-drop
  rx:host-eth0
02:04:11:153235: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 91

02:04:11:153198: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 108 snaplen 108 mac 66 net 80
      sec 0x5f35c656 nsec 0xa3d566f vlan 0 vlan_tpid 0
02:04:11:153209: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:153222: error-drop
  rx:host-eth0
02:04:11:153232: drop
  ethernet-input: l3 mac mismatch

Packet 92

02:04:11:153198: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0xa3da1c7 vlan 0 vlan_tpid 0
02:04:11:153209: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:153217: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x87e4 dscp CS0 ecn NON_ECN
    fragment id 0x5ab4, flags DONT_FRAGMENT
  TCP: 34392 -> 6443
    seq. 0xfdf364f3 ack 0xc7e97a4c
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:153225: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8658 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34392 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:153234: error-drop
  rx:host-eth0
02:04:11:153235: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 93

02:04:11:153198: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 100 snaplen 100 mac 66 net 80
      sec 0x5f35c656 nsec 0xa554968 vlan 0 vlan_tpid 0
02:04:11:153209: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:153222: error-drop
  rx:host-eth0
02:04:11:153232: drop
  ethernet-input: l3 mac mismatch

Packet 94

02:04:11:153198: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0xa55c7a7 vlan 0 vlan_tpid 0
02:04:11:153209: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:153217: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xbfbf dscp CS0 ecn NON_ECN
    fragment id 0x22d9, flags DONT_FRAGMENT
  TCP: 34382 -> 6443
    seq. 0x7770a23d ack 0x9c416ea5
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:153225: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b864e 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34382 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:153234: error-drop
  rx:host-eth0
02:04:11:153235: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 95

02:04:11:153198: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 96 snaplen 96 mac 66 net 80
      sec 0x5f35c656 nsec 0xa565cb0 vlan 0 vlan_tpid 0
02:04:11:153209: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:153222: error-drop
  rx:host-eth0
02:04:11:153232: drop
  ethernet-input: l3 mac mismatch

Packet 96

02:04:11:153198: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0xa568af4 vlan 0 vlan_tpid 0
02:04:11:153209: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:153217: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xbfbe dscp CS0 ecn NON_ECN
    fragment id 0x22da, flags DONT_FRAGMENT
  TCP: 34382 -> 6443
    seq. 0x7770a23d ack 0x9c416ec3
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:153225: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b864e 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34382 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:153234: error-drop
  rx:host-eth0
02:04:11:153235: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 97

02:04:11:153198: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 291 snaplen 291 mac 66 net 80
      sec 0x5f35c656 nsec 0xa6a0fe0 vlan 0 vlan_tpid 0
02:04:11:153209: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:153217: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 277, checksum 0x8b5a dscp CS0 ecn NON_ECN
    fragment id 0x565d, flags DONT_FRAGMENT
  TCP: 34394 -> 6443
    seq. 0x737d06e3 ack 0x8f0a31be
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:153225: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b865a 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34394 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:11:153234: error-drop
  rx:host-eth0
02:04:11:153235: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 98

02:04:11:153198: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0xa6a5834 vlan 0 vlan_tpid 0
02:04:11:153209: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:153222: error-drop
  rx:host-eth0
02:04:11:153232: drop
  ethernet-input: l3 mac mismatch

Packet 99

02:04:11:155760: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 116 snaplen 116 mac 66 net 80
      sec 0x5f35c656 nsec 0xa847461 vlan 0 vlan_tpid 0
02:04:11:155769: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:155774: error-drop
  rx:host-eth0
02:04:11:155779: drop
  ethernet-input: l3 mac mismatch

Packet 100

02:04:11:155760: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0xa84d106 vlan 0 vlan_tpid 0
02:04:11:155769: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:155776: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x8c3a dscp CS0 ecn NON_ECN
    fragment id 0x565e, flags DONT_FRAGMENT
  TCP: 34394 -> 6443
    seq. 0x737d07c4 ack 0x8f0a31f0
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:155781: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b865a 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34394 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:155787: error-drop
  rx:host-eth0
02:04:11:155787: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 101

02:04:11:157895: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0xaaaf4a3 vlan 0 vlan_tpid 0
02:04:11:157902: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:157908: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xe7e8 dscp CS0 ecn NON_ECN
    fragment id 0xfaaf, flags DONT_FRAGMENT
  TCP: 34350 -> 6443
    seq. 0x40a6e94d ack 0xb1f63ac6
    flags 0x11 FIN ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:157912: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b862e 0311ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34350 -> 6443 tcp flags (valid) 11 rsvd 0
02:04:11:157918: error-drop
  rx:host-eth0
02:04:11:157918: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 102

02:04:11:157895: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000001 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0xaab598d vlan 0 vlan_tpid 0
02:04:11:157902: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:157911: error-drop
  rx:host-eth0
02:04:11:157916: drop
  ethernet-input: l3 mac mismatch

Packet 103

02:04:11:165081: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0xb12d80c vlan 0 vlan_tpid 0
02:04:11:165090: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:165095: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x2657 dscp CS0 ecn NON_ECN
    fragment id 0xbc41, flags DONT_FRAGMENT
  TCP: 34344 -> 6443
    seq. 0x38186a3e ack 0x31e19d85
    flags 0x11 FIN ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:165100: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8628 0311ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34344 -> 6443 tcp flags (valid) 11 rsvd 0
02:04:11:165107: error-drop
  rx:host-eth0
02:04:11:165107: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 104

02:04:11:165081: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000001 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0xb133fad vlan 0 vlan_tpid 0
02:04:11:165090: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:165098: error-drop
  rx:host-eth0
02:04:11:165105: drop
  ethernet-input: l3 mac mismatch

Packet 105

02:04:11:214510: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 114 snaplen 114 mac 66 net 80
      sec 0x5f35c656 nsec 0xd8bca9e vlan 0 vlan_tpid 0
02:04:11:214521: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:214532: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 100, checksum 0x87b3 dscp CS0 ecn NON_ECN
    fragment id 0x5ab5, flags DONT_FRAGMENT
  TCP: 34392 -> 6443
    seq. 0xfdf364f3 ack 0xc7e97a4c
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:214541: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8658 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34392 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:11:214550: error-drop
  rx:host-eth0
02:04:11:214550: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 106

02:04:11:214510: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 227 snaplen 227 mac 66 net 80
      sec 0x5f35c656 nsec 0xdd45e5f vlan 0 vlan_tpid 0
02:04:11:214521: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:214532: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 213, checksum 0x8741 dscp CS0 ecn NON_ECN
    fragment id 0x5ab6, flags DONT_FRAGMENT
  TCP: 34392 -> 6443
    seq. 0xfdf36523 ack 0xc7e97a4c
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:214541: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8658 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34392 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:11:214550: error-drop
  rx:host-eth0
02:04:11:214550: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 107

02:04:11:214510: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0xdd7195a vlan 0 vlan_tpid 0
02:04:11:214521: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:214538: error-drop
  rx:host-eth0
02:04:11:214547: drop
  ethernet-input: l3 mac mismatch

Packet 108

02:04:11:214510: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 108 snaplen 108 mac 66 net 80
      sec 0x5f35c656 nsec 0xddeec30 vlan 0 vlan_tpid 0
02:04:11:214521: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:214538: error-drop
  rx:host-eth0
02:04:11:214547: drop
  ethernet-input: l3 mac mismatch

Packet 109

02:04:11:214510: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0xddf22ea vlan 0 vlan_tpid 0
02:04:11:214521: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:214532: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x87e1 dscp CS0 ecn NON_ECN
    fragment id 0x5ab7, flags DONT_FRAGMENT
  TCP: 34392 -> 6443
    seq. 0xfdf365c4 ack 0xc7e97a76
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:214541: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8658 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34392 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:214550: error-drop
  rx:host-eth0
02:04:11:214550: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 110

02:04:11:218865: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 275 snaplen 275 mac 66 net 80
      sec 0x5f35c656 nsec 0xe54a27d vlan 0 vlan_tpid 0
02:04:11:218873: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:218877: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 261, checksum 0x8b68 dscp CS0 ecn NON_ECN
    fragment id 0x565f, flags DONT_FRAGMENT
  TCP: 34394 -> 6443
    seq. 0x737d07c4 ack 0x8f0a31f0
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:218883: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b865a 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34394 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:11:218888: error-drop
  rx:host-eth0
02:04:11:218891: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 111

02:04:11:218865: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 274 snaplen 274 mac 66 net 80
      sec 0x5f35c656 nsec 0xe54ebde vlan 0 vlan_tpid 0
02:04:11:218873: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:218877: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 260, checksum 0xbeed dscp CS0 ecn NON_ECN
    fragment id 0x22db, flags DONT_FRAGMENT
  TCP: 34382 -> 6443
    seq. 0x7770a23d ack 0x9c416ec3
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:218883: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b864e 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34382 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:11:218888: error-drop
  rx:host-eth0
02:04:11:218891: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 112

02:04:11:222847: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c656 nsec 0xe806ae1 vlan 0 vlan_tpid 0
02:04:11:222864: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:222876: error-drop
  rx:host-eth0
02:04:11:222885: drop
  ethernet-input: l3 mac mismatch

Packet 113

02:04:11:222847: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0xe80d9eb vlan 0 vlan_tpid 0
02:04:11:222864: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:222879: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x8c38 dscp CS0 ecn NON_ECN
    fragment id 0x5660, flags DONT_FRAGMENT
  TCP: 34394 -> 6443
    seq. 0x737d0895 ack 0x8f0a3208
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:222887: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b865a 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34394 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:222895: error-drop
  rx:host-eth0
02:04:11:222896: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 114

02:04:11:222847: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c656 nsec 0xe814c56 vlan 0 vlan_tpid 0
02:04:11:222864: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:222876: error-drop
  rx:host-eth0
02:04:11:222885: drop
  ethernet-input: l3 mac mismatch

Packet 115

02:04:11:222847: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0xe817716 vlan 0 vlan_tpid 0
02:04:11:222864: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:222879: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x8c37 dscp CS0 ecn NON_ECN
    fragment id 0x5661, flags DONT_FRAGMENT
  TCP: 34394 -> 6443
    seq. 0x737d0895 ack 0x8f0a3220
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:222887: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b865a 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34394 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:222895: error-drop
  rx:host-eth0
02:04:11:222896: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 116

02:04:11:222847: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c656 nsec 0xe822170 vlan 0 vlan_tpid 0
02:04:11:222864: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:222876: error-drop
  rx:host-eth0
02:04:11:222885: drop
  ethernet-input: l3 mac mismatch

Packet 117

02:04:11:222847: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0xe8256b3 vlan 0 vlan_tpid 0
02:04:11:222864: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:222879: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x8c36 dscp CS0 ecn NON_ECN
    fragment id 0x5662, flags DONT_FRAGMENT
  TCP: 34394 -> 6443
    seq. 0x737d0895 ack 0x8f0a323a
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:222887: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b865a 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34394 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:222895: error-drop
  rx:host-eth0
02:04:11:222896: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 118

02:04:11:222847: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 100 snaplen 100 mac 66 net 80
      sec 0x5f35c656 nsec 0xe83a4bd vlan 0 vlan_tpid 0
02:04:11:222864: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:222876: error-drop
  rx:host-eth0
02:04:11:222885: drop
  ethernet-input: l3 mac mismatch

Packet 119

02:04:11:222847: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0xe83d2ce vlan 0 vlan_tpid 0
02:04:11:222864: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:222879: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x8c35 dscp CS0 ecn NON_ECN
    fragment id 0x5663, flags DONT_FRAGMENT
  TCP: 34394 -> 6443
    seq. 0x737d0895 ack 0x8f0a325c
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:222887: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b865a 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34394 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:222895: error-drop
  rx:host-eth0
02:04:11:222896: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 120

02:04:11:222847: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c656 nsec 0xe85f032 vlan 0 vlan_tpid 0
02:04:11:222864: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:222876: error-drop
  rx:host-eth0
02:04:11:222885: drop
  ethernet-input: l3 mac mismatch

Packet 121

02:04:11:222847: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0xe862a55 vlan 0 vlan_tpid 0
02:04:11:222864: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:222879: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xbfbc dscp CS0 ecn NON_ECN
    fragment id 0x22dc, flags DONT_FRAGMENT
  TCP: 34382 -> 6443
    seq. 0x7770a30d ack 0x9c416edb
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:222887: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b864e 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34382 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:222895: error-drop
  rx:host-eth0
02:04:11:222896: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 122

02:04:11:222847: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c656 nsec 0xe8747f8 vlan 0 vlan_tpid 0
02:04:11:222864: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:222876: error-drop
  rx:host-eth0
02:04:11:222885: drop
  ethernet-input: l3 mac mismatch

Packet 123

02:04:11:222847: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0xe876af9 vlan 0 vlan_tpid 0
02:04:11:222864: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:222879: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xbfbb dscp CS0 ecn NON_ECN
    fragment id 0x22dd, flags DONT_FRAGMENT
  TCP: 34382 -> 6443
    seq. 0x7770a30d ack 0x9c416ef3
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:222887: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b864e 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34382 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:222895: error-drop
  rx:host-eth0
02:04:11:222896: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 124

02:04:11:222847: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 96 snaplen 96 mac 66 net 80
      sec 0x5f35c656 nsec 0xe87d509 vlan 0 vlan_tpid 0
02:04:11:222864: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:222876: error-drop
  rx:host-eth0
02:04:11:222885: drop
  ethernet-input: l3 mac mismatch

Packet 125

02:04:11:222847: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0xe87f288 vlan 0 vlan_tpid 0
02:04:11:222864: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:222879: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xbfba dscp CS0 ecn NON_ECN
    fragment id 0x22de, flags DONT_FRAGMENT
  TCP: 34382 -> 6443
    seq. 0x7770a30d ack 0x9c416f11
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:222887: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b864e 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34382 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:222895: error-drop
  rx:host-eth0
02:04:11:222896: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 126

02:04:11:222847: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 96 snaplen 96 mac 66 net 80
      sec 0x5f35c656 nsec 0xe8842fd vlan 0 vlan_tpid 0
02:04:11:222864: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:222876: error-drop
  rx:host-eth0
02:04:11:222885: drop
  ethernet-input: l3 mac mismatch

Packet 127

02:04:11:222847: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0xe886db3 vlan 0 vlan_tpid 0
02:04:11:222864: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:222879: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xbfb9 dscp CS0 ecn NON_ECN
    fragment id 0x22df, flags DONT_FRAGMENT
  TCP: 34382 -> 6443
    seq. 0x7770a30d ack 0x9c416f2f
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:222887: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b864e 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34382 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:222895: error-drop
  rx:host-eth0
02:04:11:222896: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 128

02:04:11:246133: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c656 nsec 0xfe7fcc3 vlan 0 vlan_tpid 0
02:04:11:246144: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:246151: error-drop
  rx:host-eth0
02:04:11:246157: drop
  ethernet-input: l3 mac mismatch

Packet 129

02:04:11:246133: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0xfe90434 vlan 0 vlan_tpid 0
02:04:11:246144: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:246154: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xbfb8 dscp CS0 ecn NON_ECN
    fragment id 0x22e0, flags DONT_FRAGMENT
  TCP: 34382 -> 6443
    seq. 0x7770a30d ack 0x9c416f49
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:246159: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b864e 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34382 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:246165: error-drop
  rx:host-eth0
02:04:11:246166: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 130

02:04:11:247811: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c656 nsec 0xffc5cc8 vlan 0 vlan_tpid 0
02:04:11:247820: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:247827: error-drop
  rx:host-eth0
02:04:11:247833: drop
  ethernet-input: l3 mac mismatch

Packet 131

02:04:11:247811: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0xffd2c03 vlan 0 vlan_tpid 0
02:04:11:247820: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:247829: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xbfb7 dscp CS0 ecn NON_ECN
    fragment id 0x22e1, flags DONT_FRAGMENT
  TCP: 34382 -> 6443
    seq. 0x7770a30d ack 0x9c416f63
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:247834: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b864e 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34382 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:247839: error-drop
  rx:host-eth0
02:04:11:247840: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 132

02:04:11:248918: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 132 snaplen 132 mac 66 net 80
      sec 0x5f35c656 nsec 0x10179e80 vlan 0 vlan_tpid 0
02:04:11:248927: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:248934: error-drop
  rx:host-eth0
02:04:11:248939: drop
  ethernet-input: l3 mac mismatch

Packet 133

02:04:11:248918: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x101872a2 vlan 0 vlan_tpid 0
02:04:11:248927: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:248936: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xbfb6 dscp CS0 ecn NON_ECN
    fragment id 0x22e2, flags DONT_FRAGMENT
  TCP: 34382 -> 6443
    seq. 0x7770a30d ack 0x9c416fa5
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:248940: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b864e 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34382 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:248945: error-drop
  rx:host-eth0
02:04:11:248945: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 134

02:04:11:248918: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 134 snaplen 134 mac 66 net 80
      sec 0x5f35c656 nsec 0x101b23ce vlan 0 vlan_tpid 0
02:04:11:248927: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:248934: error-drop
  rx:host-eth0
02:04:11:248939: drop
  ethernet-input: l3 mac mismatch

Packet 135

02:04:11:248918: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x101baaf6 vlan 0 vlan_tpid 0
02:04:11:248927: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:248936: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xbfb5 dscp CS0 ecn NON_ECN
    fragment id 0x22e3, flags DONT_FRAGMENT
  TCP: 34382 -> 6443
    seq. 0x7770a30d ack 0x9c416fe9
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:248940: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b864e 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34382 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:248945: error-drop
  rx:host-eth0
02:04:11:248945: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 136

02:04:11:248918: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c656 nsec 0x101c6d51 vlan 0 vlan_tpid 0
02:04:11:248927: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:248934: error-drop
  rx:host-eth0
02:04:11:248939: drop
  ethernet-input: l3 mac mismatch

Packet 137

02:04:11:248918: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x101cc030 vlan 0 vlan_tpid 0
02:04:11:248927: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:248936: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xbfb4 dscp CS0 ecn NON_ECN
    fragment id 0x22e4, flags DONT_FRAGMENT
  TCP: 34382 -> 6443
    seq. 0x7770a30d ack 0x9c417001
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:248940: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b864e 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34382 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:248945: error-drop
  rx:host-eth0
02:04:11:248945: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 138

02:04:11:248918: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x101ce944 vlan 0 vlan_tpid 0
02:04:11:248927: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:248934: error-drop
  rx:host-eth0
02:04:11:248939: drop
  ethernet-input: l3 mac mismatch

Packet 139

02:04:11:267585: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 215 snaplen 215 mac 66 net 80
      sec 0x5f35c656 nsec 0x112cbf30 vlan 0 vlan_tpid 0
02:04:11:267590: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:267594: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 201, checksum 0x874b dscp CS0 ecn NON_ECN
    fragment id 0x5ab8, flags DONT_FRAGMENT
  TCP: 34392 -> 6443
    seq. 0xfdf365c4 ack 0xc7e97a76
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:267598: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8658 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34392 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:11:267604: error-drop
  rx:host-eth0
02:04:11:267606: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 140

02:04:11:268662: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 125 snaplen 125 mac 66 net 80
      sec 0x5f35c656 nsec 0x113ed3ca vlan 0 vlan_tpid 0
02:04:11:268670: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:268685: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 111, checksum 0x87a4 dscp CS0 ecn NON_ECN
    fragment id 0x5ab9, flags DONT_FRAGMENT
  TCP: 34392 -> 6443
    seq. 0xfdf36659 ack 0xc7e97a76
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:268690: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8658 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34392 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:11:268695: error-drop
  rx:host-eth0
02:04:11:268696: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 141

02:04:11:268662: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x113f65b1 vlan 0 vlan_tpid 0
02:04:11:268670: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:268682: error-drop
  rx:host-eth0
02:04:11:268688: drop
  ethernet-input: l3 mac mismatch

Packet 142

02:04:11:268662: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c656 nsec 0x1144d519 vlan 0 vlan_tpid 0
02:04:11:268670: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:268682: error-drop
  rx:host-eth0
02:04:11:268688: drop
  ethernet-input: l3 mac mismatch

Packet 143

02:04:11:268662: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x11450674 vlan 0 vlan_tpid 0
02:04:11:268670: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:268685: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x87de dscp CS0 ecn NON_ECN
    fragment id 0x5aba, flags DONT_FRAGMENT
  TCP: 34392 -> 6443
    seq. 0xfdf36694 ack 0xc7e97a8e
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:268690: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8658 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34392 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:268695: error-drop
  rx:host-eth0
02:04:11:268696: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 144

02:04:11:268662: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 106 snaplen 106 mac 66 net 80
      sec 0x5f35c656 nsec 0x114566ea vlan 0 vlan_tpid 0
02:04:11:268670: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:268682: error-drop
  rx:host-eth0
02:04:11:268688: drop
  ethernet-input: l3 mac mismatch

Packet 145

02:04:11:268662: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x11459216 vlan 0 vlan_tpid 0
02:04:11:268670: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:268685: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x87dd dscp CS0 ecn NON_ECN
    fragment id 0x5abb, flags DONT_FRAGMENT
  TCP: 34392 -> 6443
    seq. 0xfdf36694 ack 0xc7e97ab6
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:268690: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8658 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34392 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:268695: error-drop
  rx:host-eth0
02:04:11:268696: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 146

02:04:11:280456: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 274 snaplen 274 mac 66 net 80
      sec 0x5f35c656 nsec 0x11fb6dc9 vlan 0 vlan_tpid 0
02:04:11:280462: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:280466: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 260, checksum 0x8b64 dscp CS0 ecn NON_ECN
    fragment id 0x5664, flags DONT_FRAGMENT
  TCP: 34394 -> 6443
    seq. 0x737d0895 ack 0x8f0a325c
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:280469: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b865a 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34394 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:11:280475: error-drop
  rx:host-eth0
02:04:11:280477: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 147

02:04:11:281549: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c656 nsec 0x120553c1 vlan 0 vlan_tpid 0
02:04:11:281553: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:281558: error-drop
  rx:host-eth0
02:04:11:281562: drop
  ethernet-input: l3 mac mismatch

Packet 148

02:04:11:281549: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x1205a43b vlan 0 vlan_tpid 0
02:04:11:281553: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:281559: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x8c33 dscp CS0 ecn NON_ECN
    fragment id 0x5665, flags DONT_FRAGMENT
  TCP: 34394 -> 6443
    seq. 0x737d0965 ack 0x8f0a3276
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:281563: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b865a 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34394 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:281566: error-drop
  rx:host-eth0
02:04:11:281566: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 149

02:04:11:281549: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 104 snaplen 104 mac 66 net 80
      sec 0x5f35c656 nsec 0x120729e0 vlan 0 vlan_tpid 0
02:04:11:281553: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:281558: error-drop
  rx:host-eth0
02:04:11:281562: drop
  ethernet-input: l3 mac mismatch

Packet 150

02:04:11:281549: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x12079b63 vlan 0 vlan_tpid 0
02:04:11:281553: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:281559: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x8c32 dscp CS0 ecn NON_ECN
    fragment id 0x5666, flags DONT_FRAGMENT
  TCP: 34394 -> 6443
    seq. 0x737d0965 ack 0x8f0a329c
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:281563: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b865a 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34394 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:281566: error-drop
  rx:host-eth0
02:04:11:281566: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 151

02:04:11:295220: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x12d6c5d1 vlan 0 vlan_tpid 0
02:04:11:295229: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:295235: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xbfb3 dscp CS0 ecn NON_ECN
    fragment id 0x22e5, flags DONT_FRAGMENT
  TCP: 34382 -> 6443
    seq. 0x7770a30d ack 0x9c417002
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:295239: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b864e 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34382 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:295245: error-drop
  rx:host-eth0
02:04:11:295247: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 152

02:04:11:308285: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 74 snaplen 74 mac 66 net 80
      sec 0x5f35c656 nsec 0x13a601a5 vlan 0 vlan_tpid 0
02:04:11:308295: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:308302: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 60, checksum 0x0ce2 dscp CS0 ecn NON_ECN
    fragment id 0xd5ae, flags DONT_FRAGMENT
  TCP: 34424 -> 6443
    seq. 0x008a42e3 ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 64240, checksum 0x0000
02:04:11:308307: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8678 0302ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34424 -> 6443 tcp flags (valid) 02 rsvd 0
02:04:11:308317: error-drop
  rx:host-eth0
02:04:11:308317: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 153

02:04:11:308285: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 74 snaplen 74 mac 66 net 80
      sec 0x5f35c656 nsec 0x13a67dc2 vlan 0 vlan_tpid 0
02:04:11:308295: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:308306: error-drop
  rx:host-eth0
02:04:11:308314: drop
  ethernet-input: l3 mac mismatch

Packet 154

02:04:11:308285: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x13a6bd07 vlan 0 vlan_tpid 0
02:04:11:308295: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:308302: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x0ce9 dscp CS0 ecn NON_ECN
    fragment id 0xd5af, flags DONT_FRAGMENT
  TCP: 34424 -> 6443
    seq. 0x008a42e4 ack 0x9aa2001f
    flags 0x10 ACK, tcp header: 32 bytes
    window 502, checksum 0x0000
02:04:11:308307: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8678 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34424 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:308317: error-drop
  rx:host-eth0
02:04:11:308317: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 155

02:04:11:312818: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c656 nsec 0x13ed9b7e vlan 0 vlan_tpid 0
02:04:11:312838: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:312845: error-drop
  rx:host-eth0
02:04:11:312851: drop
  ethernet-input: l3 mac mismatch

Packet 156

02:04:11:312818: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x13ee1e4d vlan 0 vlan_tpid 0
02:04:11:312838: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:312847: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x87dc dscp CS0 ecn NON_ECN
    fragment id 0x5abc, flags DONT_FRAGMENT
  TCP: 34392 -> 6443
    seq. 0xfdf36694 ack 0xc7e97ad0
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:312853: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8658 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34392 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:312858: error-drop
  rx:host-eth0
02:04:11:312859: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 157

02:04:11:313937: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c656 nsec 0x13f0521c vlan 0 vlan_tpid 0
02:04:11:313946: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:313952: error-drop
  rx:host-eth0
02:04:11:313958: drop
  ethernet-input: l3 mac mismatch

Packet 158

02:04:11:313937: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x13f0884d vlan 0 vlan_tpid 0
02:04:11:313946: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:313955: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x87db dscp CS0 ecn NON_ECN
    fragment id 0x5abd, flags DONT_FRAGMENT
  TCP: 34392 -> 6443
    seq. 0xfdf36694 ack 0xc7e97aea
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:313959: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8658 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34392 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:313965: error-drop
  rx:host-eth0
02:04:11:313966: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 159

02:04:11:315021: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 96 snaplen 96 mac 66 net 80
      sec 0x5f35c656 nsec 0x1407621d vlan 0 vlan_tpid 0
02:04:11:315034: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:315046: error-drop
  rx:host-eth0
02:04:11:315054: drop
  ethernet-input: l3 mac mismatch

Packet 160

02:04:11:315021: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x1408eeb7 vlan 0 vlan_tpid 0
02:04:11:315034: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:315050: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x87da dscp CS0 ecn NON_ECN
    fragment id 0x5abe, flags DONT_FRAGMENT
  TCP: 34392 -> 6443
    seq. 0xfdf36694 ack 0xc7e97b08
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:315056: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8658 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34392 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:315061: error-drop
  rx:host-eth0
02:04:11:315062: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 161

02:04:11:315021: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 138 snaplen 138 mac 66 net 80
      sec 0x5f35c656 nsec 0x140b4070 vlan 0 vlan_tpid 0
02:04:11:315034: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:315046: error-drop
  rx:host-eth0
02:04:11:315054: drop
  ethernet-input: l3 mac mismatch

Packet 162

02:04:11:315021: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x140ba94f vlan 0 vlan_tpid 0
02:04:11:315034: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:315050: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x87d9 dscp CS0 ecn NON_ECN
    fragment id 0x5abf, flags DONT_FRAGMENT
  TCP: 34392 -> 6443
    seq. 0xfdf36694 ack 0xc7e97b50
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:315056: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8658 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34392 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:315061: error-drop
  rx:host-eth0
02:04:11:315062: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 163

02:04:11:315021: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 96 snaplen 96 mac 66 net 80
      sec 0x5f35c656 nsec 0x140c2ea9 vlan 0 vlan_tpid 0
02:04:11:315034: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:315046: error-drop
  rx:host-eth0
02:04:11:315054: drop
  ethernet-input: l3 mac mismatch

Packet 164

02:04:11:315021: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x140c746d vlan 0 vlan_tpid 0
02:04:11:315034: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:315050: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x87d8 dscp CS0 ecn NON_ECN
    fragment id 0x5ac0, flags DONT_FRAGMENT
  TCP: 34392 -> 6443
    seq. 0xfdf36694 ack 0xc7e97b6e
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:315056: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8658 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34392 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:315061: error-drop
  rx:host-eth0
02:04:11:315062: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 165

02:04:11:315021: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 98 snaplen 98 mac 66 net 80
      sec 0x5f35c656 nsec 0x140cf7ee vlan 0 vlan_tpid 0
02:04:11:315034: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:315046: error-drop
  rx:host-eth0
02:04:11:315054: drop
  ethernet-input: l3 mac mismatch

Packet 166

02:04:11:315021: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c656 nsec 0x140d3301 vlan 0 vlan_tpid 0
02:04:11:315034: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:315046: error-drop
  rx:host-eth0
02:04:11:315054: drop
  ethernet-input: l3 mac mismatch

Packet 167

02:04:11:315021: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x140d3acf vlan 0 vlan_tpid 0
02:04:11:315034: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:315050: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x87d7 dscp CS0 ecn NON_ECN
    fragment id 0x5ac1, flags DONT_FRAGMENT
  TCP: 34392 -> 6443
    seq. 0xfdf36694 ack 0xc7e97b8e
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:315056: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8658 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34392 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:315061: error-drop
  rx:host-eth0
02:04:11:315062: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 168

02:04:11:315021: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 96 snaplen 96 mac 66 net 80
      sec 0x5f35c656 nsec 0x140d6142 vlan 0 vlan_tpid 0
02:04:11:315034: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:315046: error-drop
  rx:host-eth0
02:04:11:315054: drop
  ethernet-input: l3 mac mismatch

Packet 169

02:04:11:315021: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c656 nsec 0x140d8fc7 vlan 0 vlan_tpid 0
02:04:11:315034: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:315046: error-drop
  rx:host-eth0
02:04:11:315054: drop
  ethernet-input: l3 mac mismatch

Packet 170

02:04:11:315021: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x140d9f08 vlan 0 vlan_tpid 0
02:04:11:315034: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:315050: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x87d6 dscp CS0 ecn NON_ECN
    fragment id 0x5ac2, flags DONT_FRAGMENT
  TCP: 34392 -> 6443
    seq. 0xfdf36694 ack 0xc7e97bc4
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:315056: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8658 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34392 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:315061: error-drop
  rx:host-eth0
02:04:11:315062: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 171

02:04:11:315021: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x140de03c vlan 0 vlan_tpid 0
02:04:11:315034: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:315050: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x87d5 dscp CS0 ecn NON_ECN
    fragment id 0x5ac3, flags DONT_FRAGMENT
  TCP: 34392 -> 6443
    seq. 0xfdf36694 ack 0xc7e97bde
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:315056: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8658 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34392 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:315061: error-drop
  rx:host-eth0
02:04:11:315062: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 172

02:04:11:315021: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c656 nsec 0x140df4cd vlan 0 vlan_tpid 0
02:04:11:315034: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:315046: error-drop
  rx:host-eth0
02:04:11:315054: drop
  ethernet-input: l3 mac mismatch

Packet 173

02:04:11:315021: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x140e735e vlan 0 vlan_tpid 0
02:04:11:315034: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:315050: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x87d4 dscp CS0 ecn NON_ECN
    fragment id 0x5ac4, flags DONT_FRAGMENT
  TCP: 34392 -> 6443
    seq. 0xfdf36694 ack 0xc7e97bf6
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:315056: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8658 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34392 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:315061: error-drop
  rx:host-eth0
02:04:11:315062: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 174

02:04:11:315021: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x140f1e09 vlan 0 vlan_tpid 0
02:04:11:315034: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:315046: error-drop
  rx:host-eth0
02:04:11:315054: drop
  ethernet-input: l3 mac mismatch

Packet 175

02:04:11:317176: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 96 snaplen 96 mac 66 net 80
      sec 0x5f35c656 nsec 0x142bee5f vlan 0 vlan_tpid 0
02:04:11:317185: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:317193: error-drop
  rx:host-eth0
02:04:11:317199: drop
  ethernet-input: l3 mac mismatch

Packet 176

02:04:11:317176: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x142c3490 vlan 0 vlan_tpid 0
02:04:11:317185: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:317196: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x8c31 dscp CS0 ecn NON_ECN
    fragment id 0x5667, flags DONT_FRAGMENT
  TCP: 34394 -> 6443
    seq. 0x737d0965 ack 0x8f0a32ba
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:317201: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b865a 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34394 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:317207: error-drop
  rx:host-eth0
02:04:11:317208: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 177

02:04:11:318285: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 130 snaplen 130 mac 66 net 80
      sec 0x5f35c656 nsec 0x143c534a vlan 0 vlan_tpid 0
02:04:11:318298: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:318306: error-drop
  rx:host-eth0
02:04:11:318314: drop
  ethernet-input: l3 mac mismatch

Packet 178

02:04:11:318285: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x143ca508 vlan 0 vlan_tpid 0
02:04:11:318298: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:318309: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x8c30 dscp CS0 ecn NON_ECN
    fragment id 0x5668, flags DONT_FRAGMENT
  TCP: 34394 -> 6443
    seq. 0x737d0965 ack 0x8f0a32fa
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:318316: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b865a 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34394 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:318322: error-drop
  rx:host-eth0
02:04:11:318323: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 179

02:04:11:318285: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 100 snaplen 100 mac 66 net 80
      sec 0x5f35c656 nsec 0x143d26cc vlan 0 vlan_tpid 0
02:04:11:318298: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:318306: error-drop
  rx:host-eth0
02:04:11:318314: drop
  ethernet-input: l3 mac mismatch

Packet 180

02:04:11:318285: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c656 nsec 0x143d6a72 vlan 0 vlan_tpid 0
02:04:11:318298: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:318306: error-drop
  rx:host-eth0
02:04:11:318314: drop
  ethernet-input: l3 mac mismatch

Packet 181

02:04:11:318285: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x143dab93 vlan 0 vlan_tpid 0
02:04:11:318298: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:318309: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x8c2f dscp CS0 ecn NON_ECN
    fragment id 0x5669, flags DONT_FRAGMENT
  TCP: 34394 -> 6443
    seq. 0x737d0965 ack 0x8f0a3336
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:318316: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b865a 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34394 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:318322: error-drop
  rx:host-eth0
02:04:11:318323: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 182

02:04:11:318285: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c656 nsec 0x143dbcce vlan 0 vlan_tpid 0
02:04:11:318298: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:318306: error-drop
  rx:host-eth0
02:04:11:318314: drop
  ethernet-input: l3 mac mismatch

Packet 183

02:04:11:318285: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x143e094f vlan 0 vlan_tpid 0
02:04:11:318298: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:318309: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x8c2e dscp CS0 ecn NON_ECN
    fragment id 0x566a, flags DONT_FRAGMENT
  TCP: 34394 -> 6443
    seq. 0x737d0965 ack 0x8f0a3350
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:318316: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b865a 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34394 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:318322: error-drop
  rx:host-eth0
02:04:11:318323: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 184

02:04:11:318285: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 104 snaplen 104 mac 66 net 80
      sec 0x5f35c656 nsec 0x143e2b59 vlan 0 vlan_tpid 0
02:04:11:318298: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:318306: error-drop
  rx:host-eth0
02:04:11:318314: drop
  ethernet-input: l3 mac mismatch

Packet 185

02:04:11:318285: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x143e5203 vlan 0 vlan_tpid 0
02:04:11:318298: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:318309: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x8c2d dscp CS0 ecn NON_ECN
    fragment id 0x566b, flags DONT_FRAGMENT
  TCP: 34394 -> 6443
    seq. 0x737d0965 ack 0x8f0a3376
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:318316: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b865a 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34394 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:318322: error-drop
  rx:host-eth0
02:04:11:318323: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 186

02:04:11:318285: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 100 snaplen 100 mac 66 net 80
      sec 0x5f35c656 nsec 0x143e60dd vlan 0 vlan_tpid 0
02:04:11:318298: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:318306: error-drop
  rx:host-eth0
02:04:11:318314: drop
  ethernet-input: l3 mac mismatch

Packet 187

02:04:11:318285: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x143e9098 vlan 0 vlan_tpid 0
02:04:11:318298: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:318309: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x8c2c dscp CS0 ecn NON_ECN
    fragment id 0x566c, flags DONT_FRAGMENT
  TCP: 34394 -> 6443
    seq. 0x737d0965 ack 0x8f0a3398
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:318316: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b865a 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34394 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:318322: error-drop
  rx:host-eth0
02:04:11:318323: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 188

02:04:11:318285: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c656 nsec 0x1441b8ee vlan 0 vlan_tpid 0
02:04:11:318298: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:318306: error-drop
  rx:host-eth0
02:04:11:318314: drop
  ethernet-input: l3 mac mismatch

Packet 189

02:04:11:318285: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x1442273b vlan 0 vlan_tpid 0
02:04:11:318298: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:318309: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x8c2b dscp CS0 ecn NON_ECN
    fragment id 0x566d, flags DONT_FRAGMENT
  TCP: 34394 -> 6443
    seq. 0x737d0965 ack 0x8f0a33b0
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:318316: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b865a 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34394 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:318322: error-drop
  rx:host-eth0
02:04:11:318323: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 190

02:04:11:319397: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x14423e89 vlan 0 vlan_tpid 0
02:04:11:319400: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:319403: error-drop
  rx:host-eth0
02:04:11:319405: drop
  ethernet-input: l3 mac mismatch

Packet 191

02:04:11:359489: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x16a745bb vlan 0 vlan_tpid 0
02:04:11:359497: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:359502: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x8c2a dscp CS0 ecn NON_ECN
    fragment id 0x566e, flags DONT_FRAGMENT
  TCP: 34394 -> 6443
    seq. 0x737d0965 ack 0x8f0a33b1
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:359507: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b865a 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34394 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:359514: error-drop
  rx:host-eth0
02:04:11:359516: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 192

02:04:11:359489: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x16a7641e vlan 0 vlan_tpid 0
02:04:11:359497: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:359502: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x87d3 dscp CS0 ecn NON_ECN
    fragment id 0x5ac5, flags DONT_FRAGMENT
  TCP: 34392 -> 6443
    seq. 0xfdf36694 ack 0xc7e97bf7
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:359507: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8658 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34392 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:359514: error-drop
  rx:host-eth0
02:04:11:359516: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 193

02:04:11:362781: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 305 snaplen 305 mac 66 net 80
      sec 0x5f35c656 nsec 0x16dfb225 vlan 0 vlan_tpid 0
02:04:11:362786: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:362791: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 291, checksum 0x0bf9 dscp CS0 ecn NON_ECN
    fragment id 0xd5b0, flags DONT_FRAGMENT
  TCP: 34424 -> 6443
    seq. 0x008a42e4 ack 0x9aa2001f
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 502, checksum 0x0000
02:04:11:362795: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8678 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34424 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:11:362802: error-drop
  rx:host-eth0
02:04:11:362803: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 194

02:04:11:362781: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x16e00c7f vlan 0 vlan_tpid 0
02:04:11:362786: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:362793: error-drop
  rx:host-eth0
02:04:11:362800: drop
  ethernet-input: l3 mac mismatch

Packet 195

02:04:11:366051: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 1647 snaplen 1647 mac 66 net 80
      sec 0x5f35c656 nsec 0x1719add2 vlan 0 vlan_tpid 0
02:04:11:366057: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:366061: error-drop
  rx:host-eth0
02:04:11:366095: drop
  ethernet-input: l3 mac mismatch

Packet 196

02:04:11:366051: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x171a235e vlan 0 vlan_tpid 0
02:04:11:366057: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:366092: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x0ce7 dscp CS0 ecn NON_ECN
    fragment id 0xd5b1, flags DONT_FRAGMENT
  TCP: 34424 -> 6443
    seq. 0x008a43d3 ack 0x9aa2064c
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:366096: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8678 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34424 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:366100: error-drop
  rx:host-eth0
02:04:11:366101: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 197

02:04:11:373865: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 74 snaplen 74 mac 66 net 80
      sec 0x5f35c656 nsec 0x178ae1e4 vlan 0 vlan_tpid 0
02:04:11:373875: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:373887: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 60, checksum 0x06e7 dscp CS0 ecn NON_ECN
    fragment id 0xdba9, flags DONT_FRAGMENT
  TCP: 34432 -> 6443
    seq. 0xb14e08ff ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 64240, checksum 0x0000
02:04:11:373894: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8680 0302ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34432 -> 6443 tcp flags (valid) 02 rsvd 0
02:04:11:373899: error-drop
  rx:host-eth0
02:04:11:373901: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 198

02:04:11:373865: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 74 snaplen 74 mac 66 net 80
      sec 0x5f35c656 nsec 0x178b8671 vlan 0 vlan_tpid 0
02:04:11:373875: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:373884: error-drop
  rx:host-eth0
02:04:11:373892: drop
  ethernet-input: l3 mac mismatch

Packet 199

02:04:11:373865: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x178be836 vlan 0 vlan_tpid 0
02:04:11:373875: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:373887: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x06ee dscp CS0 ecn NON_ECN
    fragment id 0xdbaa, flags DONT_FRAGMENT
  TCP: 34432 -> 6443
    seq. 0xb14e0900 ack 0x488812c7
    flags 0x10 ACK, tcp header: 32 bytes
    window 502, checksum 0x0000
02:04:11:373894: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8680 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34432 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:373899: error-drop
  rx:host-eth0
02:04:11:373901: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 200

02:04:11:373865: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c656 nsec 0x178d9803 vlan 0 vlan_tpid 0
02:04:11:373875: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:373887: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 76, checksum 0x87ba dscp CS0 ecn NON_ECN
    fragment id 0x5ac6, flags DONT_FRAGMENT
  TCP: 34392 -> 6443
    seq. 0xfdf36694 ack 0xc7e97bf7
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:373894: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8658 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34392 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:11:373899: error-drop
  rx:host-eth0
02:04:11:373901: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 201

02:04:11:373865: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000001 len 54 snaplen 54 mac 66 net 80
      sec 0x5f35c656 nsec 0x178dd652 vlan 0 vlan_tpid 0
02:04:11:373875: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:373884: error-drop
  rx:host-eth0
02:04:11:373892: drop
  ethernet-input: l3 mac mismatch

Packet 202

02:04:11:373865: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 318 snaplen 318 mac 66 net 80
      sec 0x5f35c656 nsec 0x178f4793 vlan 0 vlan_tpid 0
02:04:11:373875: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:373887: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 304, checksum 0x8b2d dscp CS0 ecn NON_ECN
    fragment id 0x566f, flags DONT_FRAGMENT
  TCP: 34394 -> 6443
    seq. 0x737d0965 ack 0x8f0a33b1
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:373894: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b865a 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34394 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:11:373899: error-drop
  rx:host-eth0
02:04:11:373901: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 203

02:04:11:373865: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000001 len 54 snaplen 54 mac 66 net 80
      sec 0x5f35c656 nsec 0x178f78cd vlan 0 vlan_tpid 0
02:04:11:373875: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:373884: error-drop
  rx:host-eth0
02:04:11:373892: drop
  ethernet-input: l3 mac mismatch

Packet 204

02:04:11:375144: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 74 snaplen 74 mac 66 net 80
      sec 0x5f35c656 nsec 0x17926db1 vlan 0 vlan_tpid 0
02:04:11:375155: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:375162: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 60, checksum 0x498c dscp CS0 ecn NON_ECN
    fragment id 0x9904, flags DONT_FRAGMENT
  TCP: 34434 -> 6443
    seq. 0x813c1a3f ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 64240, checksum 0x0000
02:04:11:375170: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8682 0302ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34434 -> 6443 tcp flags (valid) 02 rsvd 0
02:04:11:375178: error-drop
  rx:host-eth0
02:04:11:375203: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 205

02:04:11:375144: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 74 snaplen 74 mac 66 net 80
      sec 0x5f35c656 nsec 0x1792f642 vlan 0 vlan_tpid 0
02:04:11:375155: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:375168: error-drop
  rx:host-eth0
02:04:11:375176: drop
  ethernet-input: l3 mac mismatch

Packet 206

02:04:11:375144: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x17934a63 vlan 0 vlan_tpid 0
02:04:11:375155: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:375162: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x4993 dscp CS0 ecn NON_ECN
    fragment id 0x9905, flags DONT_FRAGMENT
  TCP: 34434 -> 6443
    seq. 0x813c1a40 ack 0xdd005358
    flags 0x10 ACK, tcp header: 32 bytes
    window 502, checksum 0x0000
02:04:11:375170: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8682 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34434 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:375178: error-drop
  rx:host-eth0
02:04:11:375203: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 207

02:04:11:432402: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 305 snaplen 305 mac 66 net 80
      sec 0x5f35c656 nsec 0x1ac677b4 vlan 0 vlan_tpid 0
02:04:11:432414: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:432429: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 291, checksum 0x05fe dscp CS0 ecn NON_ECN
    fragment id 0xdbab, flags DONT_FRAGMENT
  TCP: 34432 -> 6443
    seq. 0xb14e0900 ack 0x488812c7
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 502, checksum 0x0000
02:04:11:432436: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8680 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34432 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:11:432444: error-drop
  rx:host-eth0
02:04:11:432445: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 208

02:04:11:432402: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x1ac7187a vlan 0 vlan_tpid 0
02:04:11:432414: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:432425: error-drop
  rx:host-eth0
02:04:11:432434: drop
  ethernet-input: l3 mac mismatch

Packet 209

02:04:11:432402: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 305 snaplen 305 mac 66 net 80
      sec 0x5f35c656 nsec 0x1ac85d7a vlan 0 vlan_tpid 0
02:04:11:432414: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:432429: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 291, checksum 0x48a3 dscp CS0 ecn NON_ECN
    fragment id 0x9906, flags DONT_FRAGMENT
  TCP: 34434 -> 6443
    seq. 0x813c1a40 ack 0xdd005358
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 502, checksum 0x0000
02:04:11:432436: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8682 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34434 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:11:432444: error-drop
  rx:host-eth0
02:04:11:432445: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 210

02:04:11:432402: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x1ac89458 vlan 0 vlan_tpid 0
02:04:11:432414: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:432425: error-drop
  rx:host-eth0
02:04:11:432434: drop
  ethernet-input: l3 mac mismatch

Packet 211

02:04:11:432402: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 1647 snaplen 1647 mac 66 net 80
      sec 0x5f35c656 nsec 0x1b0879e9 vlan 0 vlan_tpid 0
02:04:11:432414: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:432425: error-drop
  rx:host-eth0
02:04:11:432434: drop
  ethernet-input: l3 mac mismatch

Packet 212

02:04:11:432402: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x1b08cec2 vlan 0 vlan_tpid 0
02:04:11:432414: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:432429: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x06ec dscp CS0 ecn NON_ECN
    fragment id 0xdbac, flags DONT_FRAGMENT
  TCP: 34432 -> 6443
    seq. 0xb14e09ef ack 0x488818f4
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:432436: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8680 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34432 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:432444: error-drop
  rx:host-eth0
02:04:11:432445: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 213

02:04:11:432402: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 1647 snaplen 1647 mac 66 net 80
      sec 0x5f35c656 nsec 0x1b0c0a4d vlan 0 vlan_tpid 0
02:04:11:432414: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:432425: error-drop
  rx:host-eth0
02:04:11:432434: drop
  ethernet-input: l3 mac mismatch

Packet 214

02:04:11:432402: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x1b0c50f6 vlan 0 vlan_tpid 0
02:04:11:432414: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:432429: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x4991 dscp CS0 ecn NON_ECN
    fragment id 0x9907, flags DONT_FRAGMENT
  TCP: 34434 -> 6443
    seq. 0x813c1b2f ack 0xdd005985
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:432436: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8682 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34434 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:432444: error-drop
  rx:host-eth0
02:04:11:432445: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 215

02:04:11:438188: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 1721 snaplen 1721 mac 66 net 80
      sec 0x5f35c656 nsec 0x1b57b788 vlan 0 vlan_tpid 0
02:04:11:438197: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:438204: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 1707, checksum 0x066f dscp CS0 ecn NON_ECN
    fragment id 0xd5b2, flags DONT_FRAGMENT
  TCP: 34424 -> 6443
    seq. 0x008a43d3 ack 0x9aa2064c
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:438209: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8678 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34424 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:11:438217: error-drop
  rx:host-eth0
02:04:11:438217: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 216

02:04:11:438188: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x1b5828c2 vlan 0 vlan_tpid 0
02:04:11:438197: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:438208: error-drop
  rx:host-eth0
02:04:11:438214: drop
  ethernet-input: l3 mac mismatch

Packet 217

02:04:11:450711: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 247 snaplen 247 mac 66 net 80
      sec 0x5f35c656 nsec 0x1c22851e vlan 0 vlan_tpid 0
02:04:11:450721: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:450728: error-drop
  rx:host-eth0
02:04:11:450734: drop
  ethernet-input: l3 mac mismatch

Packet 218

02:04:11:450711: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x1c246edc vlan 0 vlan_tpid 0
02:04:11:450721: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:450731: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x0ce4 dscp CS0 ecn NON_ECN
    fragment id 0xd5b4, flags DONT_FRAGMENT
  TCP: 34424 -> 6443
    seq. 0x008a4a4a ack 0x9aa20701
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:450737: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8678 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34424 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:450744: error-drop
  rx:host-eth0
02:04:11:450745: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 219

02:04:11:504390: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 1716 snaplen 1716 mac 66 net 80
      sec 0x5f35c656 nsec 0x1f4ad4b7 vlan 0 vlan_tpid 0
02:04:11:504406: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:504425: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 1702, checksum 0x0079 dscp CS0 ecn NON_ECN
    fragment id 0xdbad, flags DONT_FRAGMENT
  TCP: 34432 -> 6443
    seq. 0xb14e09ef ack 0x488818f4
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:504435: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8680 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34432 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:11:504447: error-drop
  rx:host-eth0
02:04:11:504448: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 220

02:04:11:504390: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x1f4b6185 vlan 0 vlan_tpid 0
02:04:11:504406: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:504420: error-drop
  rx:host-eth0
02:04:11:504432: drop
  ethernet-input: l3 mac mismatch

Packet 221

02:04:11:504390: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 1721 snaplen 1721 mac 66 net 80
      sec 0x5f35c656 nsec 0x1f4c54a3 vlan 0 vlan_tpid 0
02:04:11:504406: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:504425: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 1707, checksum 0x4319 dscp CS0 ecn NON_ECN
    fragment id 0x9908, flags DONT_FRAGMENT
  TCP: 34434 -> 6443
    seq. 0x813c1b2f ack 0xdd005985
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:504435: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8682 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34434 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:11:504447: error-drop
  rx:host-eth0
02:04:11:504448: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 222

02:04:11:504390: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x1f4c8ede vlan 0 vlan_tpid 0
02:04:11:504406: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:504420: error-drop
  rx:host-eth0
02:04:11:504432: drop
  ethernet-input: l3 mac mismatch

Packet 223

02:04:11:507551: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 140 snaplen 140 mac 66 net 80
      sec 0x5f35c656 nsec 0x1f809f7b vlan 0 vlan_tpid 0
02:04:11:507565: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:507576: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 126, checksum 0x0c99 dscp CS0 ecn NON_ECN
    fragment id 0xd5b5, flags DONT_FRAGMENT
  TCP: 34424 -> 6443
    seq. 0x008a4a4a ack 0x9aa20701
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:507585: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8678 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34424 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:11:507597: error-drop
  rx:host-eth0
02:04:11:507598: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 224

02:04:11:507551: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x1f80f8c0 vlan 0 vlan_tpid 0
02:04:11:507565: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:507582: error-drop
  rx:host-eth0
02:04:11:507593: drop
  ethernet-input: l3 mac mismatch

Packet 225

02:04:11:514875: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 217 snaplen 217 mac 66 net 80
      sec 0x5f35c656 nsec 0x1fb4efc8 vlan 0 vlan_tpid 0
02:04:11:514888: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:514895: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 203, checksum 0x0c4b dscp CS0 ecn NON_ECN
    fragment id 0xd5b6, flags DONT_FRAGMENT
  TCP: 34424 -> 6443
    seq. 0x008a4a94 ack 0x9aa20701
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:514902: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8678 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34424 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:11:514910: error-drop
  rx:host-eth0
02:04:11:514911: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 226

02:04:11:514875: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x1fb51d5a vlan 0 vlan_tpid 0
02:04:11:514888: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:514900: error-drop
  rx:host-eth0
02:04:11:514908: drop
  ethernet-input: l3 mac mismatch

Packet 227

02:04:11:521434: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c656 nsec 0x20296a9e vlan 0 vlan_tpid 0
02:04:11:521447: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:521464: error-drop
  rx:host-eth0
02:04:11:521472: drop
  ethernet-input: l3 mac mismatch

Packet 228

02:04:11:521434: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x2029c163 vlan 0 vlan_tpid 0
02:04:11:521447: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:521457: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x0ce1 dscp CS0 ecn NON_ECN
    fragment id 0xd5b7, flags DONT_FRAGMENT
  TCP: 34424 -> 6443
    seq. 0x008a4b2b ack 0x9aa20719
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:521466: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8678 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34424 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:521474: error-drop
  rx:host-eth0
02:04:11:521475: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 229

02:04:11:521434: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 94 snaplen 94 mac 66 net 80
      sec 0x5f35c656 nsec 0x202a2f55 vlan 0 vlan_tpid 0
02:04:11:521447: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:521464: error-drop
  rx:host-eth0
02:04:11:521472: drop
  ethernet-input: l3 mac mismatch

Packet 230

02:04:11:521434: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x202a54da vlan 0 vlan_tpid 0
02:04:11:521447: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:521457: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x0ce0 dscp CS0 ecn NON_ECN
    fragment id 0xd5b8, flags DONT_FRAGMENT
  TCP: 34424 -> 6443
    seq. 0x008a4b2b ack 0x9aa20735
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:521466: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8678 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34424 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:521474: error-drop
  rx:host-eth0
02:04:11:521475: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 231

02:04:11:521434: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c656 nsec 0x202a9796 vlan 0 vlan_tpid 0
02:04:11:521447: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:521464: error-drop
  rx:host-eth0
02:04:11:521472: drop
  ethernet-input: l3 mac mismatch

Packet 232

02:04:11:521434: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x202ab75f vlan 0 vlan_tpid 0
02:04:11:521447: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:521457: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x0cdf dscp CS0 ecn NON_ECN
    fragment id 0xd5b9, flags DONT_FRAGMENT
  TCP: 34424 -> 6443
    seq. 0x008a4b2b ack 0x9aa2074f
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:521466: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8678 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34424 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:521474: error-drop
  rx:host-eth0
02:04:11:521475: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 233

02:04:11:521434: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 104 snaplen 104 mac 66 net 80
      sec 0x5f35c656 nsec 0x202de244 vlan 0 vlan_tpid 0
02:04:11:521447: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:521464: error-drop
  rx:host-eth0
02:04:11:521472: drop
  ethernet-input: l3 mac mismatch

Packet 234

02:04:11:521434: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x202e146a vlan 0 vlan_tpid 0
02:04:11:521447: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:521457: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x0cde dscp CS0 ecn NON_ECN
    fragment id 0xd5ba, flags DONT_FRAGMENT
  TCP: 34424 -> 6443
    seq. 0x008a4b2b ack 0x9aa20775
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:521466: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8678 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34424 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:521474: error-drop
  rx:host-eth0
02:04:11:521475: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 235

02:04:11:521434: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 247 snaplen 247 mac 66 net 80
      sec 0x5f35c656 nsec 0x20571906 vlan 0 vlan_tpid 0
02:04:11:521447: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:521464: error-drop
  rx:host-eth0
02:04:11:521472: drop
  ethernet-input: l3 mac mismatch

Packet 236

02:04:11:521434: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x205779b9 vlan 0 vlan_tpid 0
02:04:11:521447: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:521457: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x498e dscp CS0 ecn NON_ECN
    fragment id 0x990a, flags DONT_FRAGMENT
  TCP: 34434 -> 6443
    seq. 0x813c21a6 ack 0xdd005a3a
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:521466: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8682 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34434 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:521474: error-drop
  rx:host-eth0
02:04:11:521475: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 237

02:04:11:524908: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 247 snaplen 247 mac 66 net 80
      sec 0x5f35c656 nsec 0x2084929c vlan 0 vlan_tpid 0
02:04:11:524915: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:524921: error-drop
  rx:host-eth0
02:04:11:524925: drop
  ethernet-input: l3 mac mismatch

Packet 238

02:04:11:524908: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x2084f08c vlan 0 vlan_tpid 0
02:04:11:524915: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:524922: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x06e9 dscp CS0 ecn NON_ECN
    fragment id 0xdbaf, flags DONT_FRAGMENT
  TCP: 34432 -> 6443
    seq. 0xb14e1061 ack 0x488819a9
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:524927: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8680 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34432 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:524931: error-drop
  rx:host-eth0
02:04:11:524932: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 239

02:04:11:579437: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 275 snaplen 275 mac 66 net 80
      sec 0x5f35c656 nsec 0x23bc82d7 vlan 0 vlan_tpid 0
02:04:11:579451: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:579462: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 261, checksum 0x0c0c dscp CS0 ecn NON_ECN
    fragment id 0xd5bb, flags DONT_FRAGMENT
  TCP: 34424 -> 6443
    seq. 0x008a4b2b ack 0x9aa20775
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:579470: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8678 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34424 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:11:579685: error-drop
  rx:host-eth0
02:04:11:579687: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 240

02:04:11:579437: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c656 nsec 0x23cf4bbc vlan 0 vlan_tpid 0
02:04:11:579451: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:579467: error-drop
  rx:host-eth0
02:04:11:579680: drop
  ethernet-input: l3 mac mismatch

Packet 241

02:04:11:580769: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x23cff084 vlan 0 vlan_tpid 0
02:04:11:580780: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:580790: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x0cdc dscp CS0 ecn NON_ECN
    fragment id 0xd5bc, flags DONT_FRAGMENT
  TCP: 34424 -> 6443
    seq. 0x008a4bfc ack 0x9aa2078d
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:580799: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8678 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34424 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:580809: error-drop
  rx:host-eth0
02:04:11:580811: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 242

02:04:11:580769: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 98 snaplen 98 mac 66 net 80
      sec 0x5f35c656 nsec 0x23d148fc vlan 0 vlan_tpid 0
02:04:11:580780: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:580796: error-drop
  rx:host-eth0
02:04:11:580806: drop
  ethernet-input: l3 mac mismatch

Packet 243

02:04:11:580769: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x23d195d2 vlan 0 vlan_tpid 0
02:04:11:580780: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:580790: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x0cdb dscp CS0 ecn NON_ECN
    fragment id 0xd5bd, flags DONT_FRAGMENT
  TCP: 34424 -> 6443
    seq. 0x008a4bfc ack 0x9aa207ad
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:580799: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8678 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34424 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:580809: error-drop
  rx:host-eth0
02:04:11:580811: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 244

02:04:11:580769: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 96 snaplen 96 mac 66 net 80
      sec 0x5f35c656 nsec 0x23d20ade vlan 0 vlan_tpid 0
02:04:11:580780: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:580796: error-drop
  rx:host-eth0
02:04:11:580806: drop
  ethernet-input: l3 mac mismatch

Packet 245

02:04:11:580769: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x23d254a1 vlan 0 vlan_tpid 0
02:04:11:580780: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:580790: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x0cda dscp CS0 ecn NON_ECN
    fragment id 0xd5be, flags DONT_FRAGMENT
  TCP: 34424 -> 6443
    seq. 0x008a4bfc ack 0x9aa207cb
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:580799: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8678 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34424 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:580809: error-drop
  rx:host-eth0
02:04:11:580811: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 246

02:04:11:593075: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 238 snaplen 238 mac 66 net 80
      sec 0x5f35c656 nsec 0x248d1baf vlan 0 vlan_tpid 0
02:04:11:593087: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:593101: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 224, checksum 0x063c dscp CS0 ecn NON_ECN
    fragment id 0xdbb0, flags DONT_FRAGMENT
  TCP: 34432 -> 6443
    seq. 0xb14e1061 ack 0x488819a9
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:593109: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8680 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34432 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:11:593116: error-drop
  rx:host-eth0
02:04:11:593117: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 247

02:04:11:593075: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x248d75f8 vlan 0 vlan_tpid 0
02:04:11:593087: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:593097: error-drop
  rx:host-eth0
02:04:11:593105: drop
  ethernet-input: l3 mac mismatch

Packet 248

02:04:11:593075: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 291 snaplen 291 mac 66 net 80
      sec 0x5f35c656 nsec 0x248e321e vlan 0 vlan_tpid 0
02:04:11:593087: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:593101: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 277, checksum 0x48ac dscp CS0 ecn NON_ECN
    fragment id 0x990b, flags DONT_FRAGMENT
  TCP: 34434 -> 6443
    seq. 0x813c21a6 ack 0xdd005a3a
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:593109: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8682 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34434 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:11:593116: error-drop
  rx:host-eth0
02:04:11:593117: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 249

02:04:11:593075: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x248e565b vlan 0 vlan_tpid 0
02:04:11:593087: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:593097: error-drop
  rx:host-eth0
02:04:11:593105: drop
  ethernet-input: l3 mac mismatch

Packet 250

02:04:11:594188: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c656 nsec 0x249f635a vlan 0 vlan_tpid 0
02:04:11:594200: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:594218: error-drop
  rx:host-eth0
02:04:11:594229: drop
  ethernet-input: l3 mac mismatch

Packet 251

02:04:11:594188: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x24a0062f vlan 0 vlan_tpid 0
02:04:11:594200: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:594211: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x498c dscp CS0 ecn NON_ECN
    fragment id 0x990c, flags DONT_FRAGMENT
  TCP: 34434 -> 6443
    seq. 0x813c2287 ack 0xdd005a52
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:594221: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8682 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34434 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:594232: error-drop
  rx:host-eth0
02:04:11:594233: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 252

02:04:11:594188: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 114 snaplen 114 mac 66 net 80
      sec 0x5f35c656 nsec 0x24a091d8 vlan 0 vlan_tpid 0
02:04:11:594200: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:594218: error-drop
  rx:host-eth0
02:04:11:594229: drop
  ethernet-input: l3 mac mismatch

Packet 253

02:04:11:594188: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x24a0ce07 vlan 0 vlan_tpid 0
02:04:11:594200: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:594211: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x498b dscp CS0 ecn NON_ECN
    fragment id 0x990d, flags DONT_FRAGMENT
  TCP: 34434 -> 6443
    seq. 0x813c2287 ack 0xdd005a82
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:594221: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8682 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34434 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:594232: error-drop
  rx:host-eth0
02:04:11:594233: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 254

02:04:11:594188: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 119 snaplen 119 mac 66 net 80
      sec 0x5f35c656 nsec 0x24a5731d vlan 0 vlan_tpid 0
02:04:11:594200: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:594211: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 105, checksum 0x06b2 dscp CS0 ecn NON_ECN
    fragment id 0xdbb1, flags DONT_FRAGMENT
  TCP: 34432 -> 6443
    seq. 0xb14e110d ack 0x488819a9
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:594221: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8680 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34432 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:11:594232: error-drop
  rx:host-eth0
02:04:11:594233: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 255

02:04:11:594188: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x24a5a94d vlan 0 vlan_tpid 0
02:04:11:594200: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:594218: error-drop
  rx:host-eth0
02:04:11:594229: drop
  ethernet-input: l3 mac mismatch

Packet 256

02:04:11:595365: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 116 snaplen 116 mac 66 net 80
      sec 0x5f35c656 nsec 0x24b1bdf5 vlan 0 vlan_tpid 0
02:04:11:595374: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:595380: error-drop
  rx:host-eth0
02:04:11:595385: drop
  ethernet-input: l3 mac mismatch

Packet 257

02:04:11:595365: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x24b20552 vlan 0 vlan_tpid 0
02:04:11:595374: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:595382: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x06e6 dscp CS0 ecn NON_ECN
    fragment id 0xdbb2, flags DONT_FRAGMENT
  TCP: 34432 -> 6443
    seq. 0xb14e1142 ack 0x488819db
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:595386: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8680 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34432 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:595391: error-drop
  rx:host-eth0
02:04:11:595392: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 258

02:04:11:639991: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 166 snaplen 166 mac 66 net 80
      sec 0x5f35c656 nsec 0x276586d6 vlan 0 vlan_tpid 0
02:04:11:640004: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:640012: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 152, checksum 0x0c75 dscp CS0 ecn NON_ECN
    fragment id 0xd5bf, flags DONT_FRAGMENT
  TCP: 34424 -> 6443
    seq. 0x008a4bfc ack 0x9aa207cb
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:640019: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8678 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34424 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:11:640245: error-drop
  rx:host-eth0
02:04:11:640249: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 259

02:04:11:644975: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 174 snaplen 174 mac 66 net 80
      sec 0x5f35c656 nsec 0x27a52388 vlan 0 vlan_tpid 0
02:04:11:644989: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:645052: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 160, checksum 0x0c6c dscp CS0 ecn NON_ECN
    fragment id 0xd5c0, flags DONT_FRAGMENT
  TCP: 34424 -> 6443
    seq. 0x008a4c60 ack 0x9aa207cb
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:645064: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8678 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34424 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:11:645074: error-drop
  rx:host-eth0
02:04:11:645076: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 260

02:04:11:644975: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x27a6392d vlan 0 vlan_tpid 0
02:04:11:644989: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:645046: error-drop
  rx:host-eth0
02:04:11:645060: drop
  ethernet-input: l3 mac mismatch

Packet 261

02:04:11:644975: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c656 nsec 0x27b1e357 vlan 0 vlan_tpid 0
02:04:11:644989: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:645046: error-drop
  rx:host-eth0
02:04:11:645060: drop
  ethernet-input: l3 mac mismatch

Packet 262

02:04:11:644975: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 98 snaplen 98 mac 66 net 80
      sec 0x5f35c656 nsec 0x27b34f66 vlan 0 vlan_tpid 0
02:04:11:644989: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:645046: error-drop
  rx:host-eth0
02:04:11:645060: drop
  ethernet-input: l3 mac mismatch

Packet 263

02:04:11:644975: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x27b37e2e vlan 0 vlan_tpid 0
02:04:11:644989: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:645052: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x0cd7 dscp CS0 ecn NON_ECN
    fragment id 0xd5c1, flags DONT_FRAGMENT
  TCP: 34424 -> 6443
    seq. 0x008a4ccc ack 0x9aa207e3
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:645064: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8678 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34424 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:645074: error-drop
  rx:host-eth0
02:04:11:645076: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 264

02:04:11:644975: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x27b4a368 vlan 0 vlan_tpid 0
02:04:11:644989: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:645052: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x0cd6 dscp CS0 ecn NON_ECN
    fragment id 0xd5c2, flags DONT_FRAGMENT
  TCP: 34424 -> 6443
    seq. 0x008a4ccc ack 0x9aa20803
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:645064: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8678 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34424 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:645074: error-drop
  rx:host-eth0
02:04:11:645076: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 265

02:04:11:646157: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 96 snaplen 96 mac 66 net 80
      sec 0x5f35c656 nsec 0x27b7aea4 vlan 0 vlan_tpid 0
02:04:11:646164: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:646169: error-drop
  rx:host-eth0
02:04:11:646173: drop
  ethernet-input: l3 mac mismatch

Packet 266

02:04:11:646157: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x27b91a2f vlan 0 vlan_tpid 0
02:04:11:646164: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:646171: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x0cd5 dscp CS0 ecn NON_ECN
    fragment id 0xd5c3, flags DONT_FRAGMENT
  TCP: 34424 -> 6443
    seq. 0x008a4ccc ack 0x9aa20821
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:646175: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8678 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34424 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:646179: error-drop
  rx:host-eth0
02:04:11:646179: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 267

02:04:11:654923: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 238 snaplen 238 mac 66 net 80
      sec 0x5f35c656 nsec 0x282beb2e vlan 0 vlan_tpid 0
02:04:11:654934: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:654946: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 224, checksum 0x0639 dscp CS0 ecn NON_ECN
    fragment id 0xdbb3, flags DONT_FRAGMENT
  TCP: 34432 -> 6443
    seq. 0xb14e1142 ack 0x488819db
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:654953: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8680 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34432 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:11:654959: error-drop
  rx:host-eth0
02:04:11:654960: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 268

02:04:11:654923: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 275 snaplen 275 mac 66 net 80
      sec 0x5f35c656 nsec 0x282c95c0 vlan 0 vlan_tpid 0
02:04:11:654934: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:654946: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 261, checksum 0x48b9 dscp CS0 ecn NON_ECN
    fragment id 0x990e, flags DONT_FRAGMENT
  TCP: 34434 -> 6443
    seq. 0x813c2287 ack 0xdd005a82
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:654953: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8682 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34434 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:11:654959: error-drop
  rx:host-eth0
02:04:11:654960: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 269

02:04:11:654923: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c656 nsec 0x2836b93d vlan 0 vlan_tpid 0
02:04:11:654934: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:654943: error-drop
  rx:host-eth0
02:04:11:654951: drop
  ethernet-input: l3 mac mismatch

Packet 270

02:04:11:654923: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x28371c5f vlan 0 vlan_tpid 0
02:04:11:654934: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:654946: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x4989 dscp CS0 ecn NON_ECN
    fragment id 0x990f, flags DONT_FRAGMENT
  TCP: 34434 -> 6443
    seq. 0x813c2358 ack 0xdd005a9c
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:654953: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8682 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34434 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:654959: error-drop
  rx:host-eth0
02:04:11:654960: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 271

02:04:11:654923: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 104 snaplen 104 mac 66 net 80
      sec 0x5f35c656 nsec 0x2837afb9 vlan 0 vlan_tpid 0
02:04:11:654934: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:654943: error-drop
  rx:host-eth0
02:04:11:654951: drop
  ethernet-input: l3 mac mismatch

Packet 272

02:04:11:654923: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x2837cec0 vlan 0 vlan_tpid 0
02:04:11:654934: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:654946: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x4988 dscp CS0 ecn NON_ECN
    fragment id 0x9910, flags DONT_FRAGMENT
  TCP: 34434 -> 6443
    seq. 0x813c2358 ack 0xdd005ac2
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:654953: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8682 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34434 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:654959: error-drop
  rx:host-eth0
02:04:11:654960: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 273

02:04:11:658423: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 103 snaplen 103 mac 66 net 80
      sec 0x5f35c656 nsec 0x2873d8ce vlan 0 vlan_tpid 0
02:04:11:658435: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:658441: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 89, checksum 0x06bf dscp CS0 ecn NON_ECN
    fragment id 0xdbb4, flags DONT_FRAGMENT
  TCP: 34432 -> 6443
    seq. 0xb14e11ee ack 0x488819db
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:658445: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8680 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34432 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:11:658452: error-drop
  rx:host-eth0
02:04:11:658452: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 274

02:04:11:658423: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x287f68e3 vlan 0 vlan_tpid 0
02:04:11:658435: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:658444: error-drop
  rx:host-eth0
02:04:11:658450: drop
  ethernet-input: l3 mac mismatch

Packet 275

02:04:11:659527: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c656 nsec 0x288d4a39 vlan 0 vlan_tpid 0
02:04:11:659535: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:659549: error-drop
  rx:host-eth0
02:04:11:659557: drop
  ethernet-input: l3 mac mismatch

Packet 276

02:04:11:659527: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x288d9f7d vlan 0 vlan_tpid 0
02:04:11:659535: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:659543: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x06e3 dscp CS0 ecn NON_ECN
    fragment id 0xdbb5, flags DONT_FRAGMENT
  TCP: 34432 -> 6443
    seq. 0xb14e1213 ack 0x488819f5
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:659552: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8680 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34432 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:659559: error-drop
  rx:host-eth0
02:04:11:659559: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 277

02:04:11:659527: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 104 snaplen 104 mac 66 net 80
      sec 0x5f35c656 nsec 0x288df776 vlan 0 vlan_tpid 0
02:04:11:659535: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:659549: error-drop
  rx:host-eth0
02:04:11:659557: drop
  ethernet-input: l3 mac mismatch

Packet 278

02:04:11:659527: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x288e1642 vlan 0 vlan_tpid 0
02:04:11:659535: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:659543: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x06e2 dscp CS0 ecn NON_ECN
    fragment id 0xdbb6, flags DONT_FRAGMENT
  TCP: 34432 -> 6443
    seq. 0xb14e1213 ack 0x48881a1b
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:659552: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8680 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34432 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:659559: error-drop
  rx:host-eth0
02:04:11:659559: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 279

02:04:11:678202: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 96 snaplen 96 mac 66 net 80
      sec 0x5f35c656 nsec 0x29aa754d vlan 0 vlan_tpid 0
02:04:11:678209: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:678214: error-drop
  rx:host-eth0
02:04:11:678219: drop
  ethernet-input: l3 mac mismatch

Packet 280

02:04:11:678202: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x29ab2dbe vlan 0 vlan_tpid 0
02:04:11:678209: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:678216: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x0cd4 dscp CS0 ecn NON_ECN
    fragment id 0xd5c4, flags DONT_FRAGMENT
  TCP: 34424 -> 6443
    seq. 0x008a4ccc ack 0x9aa2083f
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:678221: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8678 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34424 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:678226: error-drop
  rx:host-eth0
02:04:11:678226: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 281

02:04:11:679691: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 96 snaplen 96 mac 66 net 80
      sec 0x5f35c656 nsec 0x29bdd8a5 vlan 0 vlan_tpid 0
02:04:11:679703: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:679762: error-drop
  rx:host-eth0
02:04:11:679769: drop
  ethernet-input: l3 mac mismatch

Packet 282

02:04:11:679691: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 130 snaplen 130 mac 66 net 80
      sec 0x5f35c656 nsec 0x29bea11b vlan 0 vlan_tpid 0
02:04:11:679703: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:679762: error-drop
  rx:host-eth0
02:04:11:679769: drop
  ethernet-input: l3 mac mismatch

Packet 283

02:04:11:679691: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x29bea6ce vlan 0 vlan_tpid 0
02:04:11:679703: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:679765: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x0cd3 dscp CS0 ecn NON_ECN
    fragment id 0xd5c5, flags DONT_FRAGMENT
  TCP: 34424 -> 6443
    seq. 0x008a4ccc ack 0x9aa2085d
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:679771: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8678 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34424 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:679777: error-drop
  rx:host-eth0
02:04:11:679777: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 284

02:04:11:679691: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 96 snaplen 96 mac 66 net 80
      sec 0x5f35c656 nsec 0x29bed3b9 vlan 0 vlan_tpid 0
02:04:11:679703: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:679762: error-drop
  rx:host-eth0
02:04:11:679769: drop
  ethernet-input: l3 mac mismatch

Packet 285

02:04:11:679691: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c656 nsec 0x29bf1420 vlan 0 vlan_tpid 0
02:04:11:679703: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:679762: error-drop
  rx:host-eth0
02:04:11:679769: drop
  ethernet-input: l3 mac mismatch

Packet 286

02:04:11:679691: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x29bf32d2 vlan 0 vlan_tpid 0
02:04:11:679703: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:679765: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x0cd2 dscp CS0 ecn NON_ECN
    fragment id 0xd5c6, flags DONT_FRAGMENT
  TCP: 34424 -> 6443
    seq. 0x008a4ccc ack 0x9aa208bb
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:679771: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8678 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34424 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:679777: error-drop
  rx:host-eth0
02:04:11:679777: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 287

02:04:11:679691: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 96 snaplen 96 mac 66 net 80
      sec 0x5f35c656 nsec 0x29bf4cc7 vlan 0 vlan_tpid 0
02:04:11:679703: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:679762: error-drop
  rx:host-eth0
02:04:11:679769: drop
  ethernet-input: l3 mac mismatch

Packet 288

02:04:11:679691: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x29bf7dba vlan 0 vlan_tpid 0
02:04:11:679703: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:679765: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x0cd1 dscp CS0 ecn NON_ECN
    fragment id 0xd5c7, flags DONT_FRAGMENT
  TCP: 34424 -> 6443
    seq. 0x008a4ccc ack 0x9aa208f3
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:679771: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8678 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34424 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:679777: error-drop
  rx:host-eth0
02:04:11:679777: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 289

02:04:11:679691: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 94 snaplen 94 mac 66 net 80
      sec 0x5f35c656 nsec 0x29c08cbe vlan 0 vlan_tpid 0
02:04:11:679703: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:679762: error-drop
  rx:host-eth0
02:04:11:679769: drop
  ethernet-input: l3 mac mismatch

Packet 290

02:04:11:679691: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x29c110e6 vlan 0 vlan_tpid 0
02:04:11:679703: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:679765: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x0cd0 dscp CS0 ecn NON_ECN
    fragment id 0xd5c8, flags DONT_FRAGMENT
  TCP: 34424 -> 6443
    seq. 0x008a4ccc ack 0x9aa2090f
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:679771: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8678 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34424 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:679777: error-drop
  rx:host-eth0
02:04:11:679777: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 291

02:04:11:679691: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 102 snaplen 102 mac 66 net 80
      sec 0x5f35c656 nsec 0x29c12d1d vlan 0 vlan_tpid 0
02:04:11:679703: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:679762: error-drop
  rx:host-eth0
02:04:11:679769: drop
  ethernet-input: l3 mac mismatch

Packet 292

02:04:11:679691: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x29c167aa vlan 0 vlan_tpid 0
02:04:11:679703: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:679765: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x0ccf dscp CS0 ecn NON_ECN
    fragment id 0xd5c9, flags DONT_FRAGMENT
  TCP: 34424 -> 6443
    seq. 0x008a4ccc ack 0x9aa20933
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:679771: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8678 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34424 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:679777: error-drop
  rx:host-eth0
02:04:11:679777: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 293

02:04:11:679691: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c656 nsec 0x29c3b3ef vlan 0 vlan_tpid 0
02:04:11:679703: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:679762: error-drop
  rx:host-eth0
02:04:11:679769: drop
  ethernet-input: l3 mac mismatch

Packet 294

02:04:11:679691: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x29c442be vlan 0 vlan_tpid 0
02:04:11:679703: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:679762: error-drop
  rx:host-eth0
02:04:11:679769: drop
  ethernet-input: l3 mac mismatch

Packet 295

02:04:11:679691: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x29c4410e vlan 0 vlan_tpid 0
02:04:11:679703: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:679765: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x0cce dscp CS0 ecn NON_ECN
    fragment id 0xd5ca, flags DONT_FRAGMENT
  TCP: 34424 -> 6443
    seq. 0x008a4ccc ack 0x9aa2094b
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:679771: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8678 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34424 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:679777: error-drop
  rx:host-eth0
02:04:11:679777: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 296

02:04:11:712239: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 274 snaplen 274 mac 66 net 80
      sec 0x5f35c656 nsec 0x2bb1327a vlan 0 vlan_tpid 0
02:04:11:712246: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:712251: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 260, checksum 0x48b7 dscp CS0 ecn NON_ECN
    fragment id 0x9911, flags DONT_FRAGMENT
  TCP: 34434 -> 6443
    seq. 0x813c2358 ack 0xdd005ac2
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:712256: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8682 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34434 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:11:712263: error-drop
  rx:host-eth0
02:04:11:712265: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 297

02:04:11:713343: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c656 nsec 0x2bbc9ef7 vlan 0 vlan_tpid 0
02:04:11:713352: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:713357: error-drop
  rx:host-eth0
02:04:11:713375: drop
  ethernet-input: l3 mac mismatch

Packet 298

02:04:11:713343: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x2bbd0bd7 vlan 0 vlan_tpid 0
02:04:11:713352: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:713371: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x4986 dscp CS0 ecn NON_ECN
    fragment id 0x9912, flags DONT_FRAGMENT
  TCP: 34434 -> 6443
    seq. 0x813c2428 ack 0xdd005adc
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:713377: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8682 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34434 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:713382: error-drop
  rx:host-eth0
02:04:11:713383: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 299

02:04:11:713343: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 104 snaplen 104 mac 66 net 80
      sec 0x5f35c656 nsec 0x2bbddf57 vlan 0 vlan_tpid 0
02:04:11:713352: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:713357: error-drop
  rx:host-eth0
02:04:11:713375: drop
  ethernet-input: l3 mac mismatch

Packet 300

02:04:11:713343: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x2bbe1124 vlan 0 vlan_tpid 0
02:04:11:713352: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:713371: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x4985 dscp CS0 ecn NON_ECN
    fragment id 0x9913, flags DONT_FRAGMENT
  TCP: 34434 -> 6443
    seq. 0x813c2428 ack 0xdd005b02
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:713377: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8682 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34434 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:713382: error-drop
  rx:host-eth0
02:04:11:713383: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 301

02:04:11:716714: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 274 snaplen 274 mac 66 net 80
      sec 0x5f35c656 nsec 0x2bf04362 vlan 0 vlan_tpid 0
02:04:11:716725: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:716731: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 260, checksum 0x0611 dscp CS0 ecn NON_ECN
    fragment id 0xdbb7, flags DONT_FRAGMENT
  TCP: 34432 -> 6443
    seq. 0xb14e1213 ack 0x48881a1b
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:716737: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8680 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34432 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:11:716746: error-drop
  rx:host-eth0
02:04:11:716749: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 302

02:04:11:718262: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c656 nsec 0x2c078cfb vlan 0 vlan_tpid 0
02:04:11:718282: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:718430: error-drop
  rx:host-eth0
02:04:11:718444: drop
  ethernet-input: l3 mac mismatch

Packet 303

02:04:11:718262: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x2c083cc6 vlan 0 vlan_tpid 0
02:04:11:718282: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:718435: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x06e0 dscp CS0 ecn NON_ECN
    fragment id 0xdbb8, flags DONT_FRAGMENT
  TCP: 34432 -> 6443
    seq. 0xb14e12e3 ack 0x48881a33
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:718447: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8680 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34432 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:718455: error-drop
  rx:host-eth0
02:04:11:718456: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 304

02:04:11:718262: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c656 nsec 0x2c09045d vlan 0 vlan_tpid 0
02:04:11:718282: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:718430: error-drop
  rx:host-eth0
02:04:11:718444: drop
  ethernet-input: l3 mac mismatch

Packet 305

02:04:11:718262: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x2c094079 vlan 0 vlan_tpid 0
02:04:11:718282: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:718435: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x06df dscp CS0 ecn NON_ECN
    fragment id 0xdbb9, flags DONT_FRAGMENT
  TCP: 34432 -> 6443
    seq. 0xb14e12e3 ack 0x48881a4b
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:718447: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8680 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34432 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:718455: error-drop
  rx:host-eth0
02:04:11:718456: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 306

02:04:11:718262: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c656 nsec 0x2c09a746 vlan 0 vlan_tpid 0
02:04:11:718282: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:718430: error-drop
  rx:host-eth0
02:04:11:718444: drop
  ethernet-input: l3 mac mismatch

Packet 307

02:04:11:718262: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x2c09db3e vlan 0 vlan_tpid 0
02:04:11:718282: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:718435: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x06de dscp CS0 ecn NON_ECN
    fragment id 0xdbba, flags DONT_FRAGMENT
  TCP: 34432 -> 6443
    seq. 0xb14e12e3 ack 0x48881a65
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:718447: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8680 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34432 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:718455: error-drop
  rx:host-eth0
02:04:11:718456: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 308

02:04:11:718262: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c656 nsec 0x2c0a3b25 vlan 0 vlan_tpid 0
02:04:11:718282: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:718430: error-drop
  rx:host-eth0
02:04:11:718444: drop
  ethernet-input: l3 mac mismatch

Packet 309

02:04:11:718262: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x2c0a6b8c vlan 0 vlan_tpid 0
02:04:11:718282: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:718435: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x06dd dscp CS0 ecn NON_ECN
    fragment id 0xdbbb, flags DONT_FRAGMENT
  TCP: 34432 -> 6443
    seq. 0xb14e12e3 ack 0x48881a7f
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:718447: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8680 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34432 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:718455: error-drop
  rx:host-eth0
02:04:11:718456: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 310

02:04:11:718262: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 96 snaplen 96 mac 66 net 80
      sec 0x5f35c656 nsec 0x2c0ac9b7 vlan 0 vlan_tpid 0
02:04:11:718282: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:718430: error-drop
  rx:host-eth0
02:04:11:718444: drop
  ethernet-input: l3 mac mismatch

Packet 311

02:04:11:718262: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x2c0b9855 vlan 0 vlan_tpid 0
02:04:11:718282: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:718435: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x06dc dscp CS0 ecn NON_ECN
    fragment id 0xdbbc, flags DONT_FRAGMENT
  TCP: 34432 -> 6443
    seq. 0xb14e12e3 ack 0x48881a9d
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:718447: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8680 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34432 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:718455: error-drop
  rx:host-eth0
02:04:11:718456: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 312

02:04:11:728277: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x2c96b68d vlan 0 vlan_tpid 0
02:04:11:728286: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:728291: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x0ccd dscp CS0 ecn NON_ECN
    fragment id 0xd5cb, flags DONT_FRAGMENT
  TCP: 34424 -> 6443
    seq. 0x008a4ccc ack 0x9aa2094c
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:728295: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8678 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34424 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:728300: error-drop
  rx:host-eth0
02:04:11:728302: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 313

02:04:11:737400: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 366 snaplen 366 mac 66 net 80
      sec 0x5f35c656 nsec 0x2d35a042 vlan 0 vlan_tpid 0
02:04:11:737408: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:737414: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 352, checksum 0x0ba0 dscp CS0 ecn NON_ECN
    fragment id 0xd5cc, flags DONT_FRAGMENT
  TCP: 34424 -> 6443
    seq. 0x008a4ccc ack 0x9aa2094c
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:737420: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8678 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34424 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:11:737429: error-drop
  rx:host-eth0
02:04:11:737429: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 314

02:04:11:737400: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000001 len 54 snaplen 54 mac 66 net 80
      sec 0x5f35c656 nsec 0x2d360985 vlan 0 vlan_tpid 0
02:04:11:737408: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:737418: error-drop
  rx:host-eth0
02:04:11:737426: drop
  ethernet-input: l3 mac mismatch

Packet 315

02:04:11:744624: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 74 snaplen 74 mac 66 net 80
      sec 0x5f35c656 nsec 0x2d9ab243 vlan 0 vlan_tpid 0
02:04:11:744633: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:744640: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 60, checksum 0x5c3e dscp CS0 ecn NON_ECN
    fragment id 0x8652, flags DONT_FRAGMENT
  TCP: 34462 -> 6443
    seq. 0x986f147a ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 64240, checksum 0x0000
02:04:11:744646: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b869e 0302ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34462 -> 6443 tcp flags (valid) 02 rsvd 0
02:04:11:744653: error-drop
  rx:host-eth0
02:04:11:744654: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 316

02:04:11:744624: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 74 snaplen 74 mac 66 net 80
      sec 0x5f35c656 nsec 0x2d9b2e28 vlan 0 vlan_tpid 0
02:04:11:744633: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:744645: error-drop
  rx:host-eth0
02:04:11:744651: drop
  ethernet-input: l3 mac mismatch

Packet 317

02:04:11:744624: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x2d9b6c4b vlan 0 vlan_tpid 0
02:04:11:744633: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:744640: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x5c45 dscp CS0 ecn NON_ECN
    fragment id 0x8653, flags DONT_FRAGMENT
  TCP: 34462 -> 6443
    seq. 0x986f147b ack 0x8fc39975
    flags 0x10 ACK, tcp header: 32 bytes
    window 502, checksum 0x0000
02:04:11:744646: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b869e 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34462 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:744653: error-drop
  rx:host-eth0
02:04:11:744654: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 318

02:04:11:763189: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c656 nsec 0x2eab28e2 vlan 0 vlan_tpid 0
02:04:11:763197: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:763205: error-drop
  rx:host-eth0
02:04:11:763210: drop
  ethernet-input: l3 mac mismatch

Packet 319

02:04:11:763189: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x2eab917f vlan 0 vlan_tpid 0
02:04:11:763197: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:763207: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x4984 dscp CS0 ecn NON_ECN
    fragment id 0x9914, flags DONT_FRAGMENT
  TCP: 34434 -> 6443
    seq. 0x813c2428 ack 0xdd005b1c
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:763212: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8682 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34434 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:763223: error-drop
  rx:host-eth0
02:04:11:763223: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 320

02:04:11:763189: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c656 nsec 0x2eb04081 vlan 0 vlan_tpid 0
02:04:11:763197: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:763205: error-drop
  rx:host-eth0
02:04:11:763210: drop
  ethernet-input: l3 mac mismatch

Packet 321

02:04:11:763189: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x2eb08db0 vlan 0 vlan_tpid 0
02:04:11:763197: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:763207: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x4983 dscp CS0 ecn NON_ECN
    fragment id 0x9915, flags DONT_FRAGMENT
  TCP: 34434 -> 6443
    seq. 0x813c2428 ack 0xdd005b36
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:763212: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8682 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34434 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:763223: error-drop
  rx:host-eth0
02:04:11:763223: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 322

02:04:11:765185: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 130 snaplen 130 mac 66 net 80
      sec 0x5f35c656 nsec 0x2ecc2f1a vlan 0 vlan_tpid 0
02:04:11:765196: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:765204: error-drop
  rx:host-eth0
02:04:11:765212: drop
  ethernet-input: l3 mac mismatch

Packet 323

02:04:11:765185: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x2ecc8748 vlan 0 vlan_tpid 0
02:04:11:765196: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:765207: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x4982 dscp CS0 ecn NON_ECN
    fragment id 0x9916, flags DONT_FRAGMENT
  TCP: 34434 -> 6443
    seq. 0x813c2428 ack 0xdd005b76
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:765215: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8682 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34434 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:765222: error-drop
  rx:host-eth0
02:04:11:765223: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 324

02:04:11:765185: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 104 snaplen 104 mac 66 net 80
      sec 0x5f35c656 nsec 0x2ece2845 vlan 0 vlan_tpid 0
02:04:11:765196: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:765204: error-drop
  rx:host-eth0
02:04:11:765212: drop
  ethernet-input: l3 mac mismatch

Packet 325

02:04:11:765185: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x2ecea255 vlan 0 vlan_tpid 0
02:04:11:765196: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:765207: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x4981 dscp CS0 ecn NON_ECN
    fragment id 0x9917, flags DONT_FRAGMENT
  TCP: 34434 -> 6443
    seq. 0x813c2428 ack 0xdd005b9c
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:765215: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8682 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34434 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:765222: error-drop
  rx:host-eth0
02:04:11:765223: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 326

02:04:11:765185: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c656 nsec 0x2ecf561e vlan 0 vlan_tpid 0
02:04:11:765196: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:765204: error-drop
  rx:host-eth0
02:04:11:765212: drop
  ethernet-input: l3 mac mismatch

Packet 327

02:04:11:765185: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x2ecfc528 vlan 0 vlan_tpid 0
02:04:11:765196: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:765207: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x4980 dscp CS0 ecn NON_ECN
    fragment id 0x9918, flags DONT_FRAGMENT
  TCP: 34434 -> 6443
    seq. 0x813c2428 ack 0xdd005bb6
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:765215: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8682 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34434 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:765222: error-drop
  rx:host-eth0
02:04:11:765223: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 328

02:04:11:765185: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 100 snaplen 100 mac 66 net 80
      sec 0x5f35c656 nsec 0x2ed05374 vlan 0 vlan_tpid 0
02:04:11:765196: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:765204: error-drop
  rx:host-eth0
02:04:11:765212: drop
  ethernet-input: l3 mac mismatch

Packet 329

02:04:11:765185: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x2ed0b1a2 vlan 0 vlan_tpid 0
02:04:11:765196: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:765207: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x497f dscp CS0 ecn NON_ECN
    fragment id 0x9919, flags DONT_FRAGMENT
  TCP: 34434 -> 6443
    seq. 0x813c2428 ack 0xdd005bd8
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:765215: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8682 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34434 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:765222: error-drop
  rx:host-eth0
02:04:11:765223: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 330

02:04:11:765185: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c656 nsec 0x2ed12e52 vlan 0 vlan_tpid 0
02:04:11:765196: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:765204: error-drop
  rx:host-eth0
02:04:11:765212: drop
  ethernet-input: l3 mac mismatch

Packet 331

02:04:11:765185: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x2ed1728f vlan 0 vlan_tpid 0
02:04:11:765196: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:765207: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x497e dscp CS0 ecn NON_ECN
    fragment id 0x991a, flags DONT_FRAGMENT
  TCP: 34434 -> 6443
    seq. 0x813c2428 ack 0xdd005bf2
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:765215: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8682 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34434 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:765222: error-drop
  rx:host-eth0
02:04:11:765223: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 332

02:04:11:765185: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 96 snaplen 96 mac 66 net 80
      sec 0x5f35c656 nsec 0x2ed1e81c vlan 0 vlan_tpid 0
02:04:11:765196: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:765204: error-drop
  rx:host-eth0
02:04:11:765212: drop
  ethernet-input: l3 mac mismatch

Packet 333

02:04:11:765185: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x2ed22f51 vlan 0 vlan_tpid 0
02:04:11:765196: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:765207: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x497d dscp CS0 ecn NON_ECN
    fragment id 0x991b, flags DONT_FRAGMENT
  TCP: 34434 -> 6443
    seq. 0x813c2428 ack 0xdd005c10
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:765215: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8682 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34434 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:765222: error-drop
  rx:host-eth0
02:04:11:765223: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 334

02:04:11:765185: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c656 nsec 0x2ed2a84f vlan 0 vlan_tpid 0
02:04:11:765196: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:765204: error-drop
  rx:host-eth0
02:04:11:765212: drop
  ethernet-input: l3 mac mismatch

Packet 335

02:04:11:765185: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x2ed2edd3 vlan 0 vlan_tpid 0
02:04:11:765196: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:765207: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x497c dscp CS0 ecn NON_ECN
    fragment id 0x991c, flags DONT_FRAGMENT
  TCP: 34434 -> 6443
    seq. 0x813c2428 ack 0xdd005c2a
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:765215: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8682 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34434 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:765222: error-drop
  rx:host-eth0
02:04:11:765223: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 336

02:04:11:765185: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c656 nsec 0x2ed3a00b vlan 0 vlan_tpid 0
02:04:11:765196: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:765204: error-drop
  rx:host-eth0
02:04:11:765212: drop
  ethernet-input: l3 mac mismatch

Packet 337

02:04:11:765185: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x2ed3f9a5 vlan 0 vlan_tpid 0
02:04:11:765196: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:765207: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x497b dscp CS0 ecn NON_ECN
    fragment id 0x991d, flags DONT_FRAGMENT
  TCP: 34434 -> 6443
    seq. 0x813c2428 ack 0xdd005c42
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:765215: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8682 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34434 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:765222: error-drop
  rx:host-eth0
02:04:11:765223: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 338

02:04:11:765185: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x2ed499cd vlan 0 vlan_tpid 0
02:04:11:765196: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:765204: error-drop
  rx:host-eth0
02:04:11:765212: drop
  ethernet-input: l3 mac mismatch

Packet 339

02:04:11:768301: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 96 snaplen 96 mac 66 net 80
      sec 0x5f35c656 nsec 0x2f0b9e75 vlan 0 vlan_tpid 0
02:04:11:768371: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:768428: error-drop
  rx:host-eth0
02:04:11:768456: drop
  ethernet-input: l3 mac mismatch

Packet 340

02:04:11:768301: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x2f0ce52e vlan 0 vlan_tpid 0
02:04:11:768371: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:768431: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x06db dscp CS0 ecn NON_ECN
    fragment id 0xdbbd, flags DONT_FRAGMENT
  TCP: 34432 -> 6443
    seq. 0xb14e12e3 ack 0x48881abb
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:768459: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8680 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34432 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:768464: error-drop
  rx:host-eth0
02:04:11:768465: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 341

02:04:11:770734: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 130 snaplen 130 mac 66 net 80
      sec 0x5f35c656 nsec 0x2f2ac95f vlan 0 vlan_tpid 0
02:04:11:770748: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:770760: error-drop
  rx:host-eth0
02:04:11:770769: drop
  ethernet-input: l3 mac mismatch

Packet 342

02:04:11:770734: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x2f2b8c54 vlan 0 vlan_tpid 0
02:04:11:770748: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:770764: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x06da dscp CS0 ecn NON_ECN
    fragment id 0xdbbe, flags DONT_FRAGMENT
  TCP: 34432 -> 6443
    seq. 0xb14e12e3 ack 0x48881afb
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:770771: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8680 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34432 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:770778: error-drop
  rx:host-eth0
02:04:11:770779: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 343

02:04:11:770734: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 104 snaplen 104 mac 66 net 80
      sec 0x5f35c656 nsec 0x2f2caf03 vlan 0 vlan_tpid 0
02:04:11:770748: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:770760: error-drop
  rx:host-eth0
02:04:11:770769: drop
  ethernet-input: l3 mac mismatch

Packet 344

02:04:11:770734: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x2f2d030f vlan 0 vlan_tpid 0
02:04:11:770748: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:770764: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x06d9 dscp CS0 ecn NON_ECN
    fragment id 0xdbbf, flags DONT_FRAGMENT
  TCP: 34432 -> 6443
    seq. 0xb14e12e3 ack 0x48881b21
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:770771: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8680 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34432 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:770778: error-drop
  rx:host-eth0
02:04:11:770779: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 345

02:04:11:770734: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c656 nsec 0x2f2daf75 vlan 0 vlan_tpid 0
02:04:11:770748: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:770760: error-drop
  rx:host-eth0
02:04:11:770769: drop
  ethernet-input: l3 mac mismatch

Packet 346

02:04:11:770734: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x2f2e06cf vlan 0 vlan_tpid 0
02:04:11:770748: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:770764: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x06d8 dscp CS0 ecn NON_ECN
    fragment id 0xdbc0, flags DONT_FRAGMENT
  TCP: 34432 -> 6443
    seq. 0xb14e12e3 ack 0x48881b3b
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:770771: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8680 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34432 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:770778: error-drop
  rx:host-eth0
02:04:11:770779: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 347

02:04:11:770734: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 96 snaplen 96 mac 66 net 80
      sec 0x5f35c656 nsec 0x2f2e8708 vlan 0 vlan_tpid 0
02:04:11:770748: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:770760: error-drop
  rx:host-eth0
02:04:11:770769: drop
  ethernet-input: l3 mac mismatch

Packet 348

02:04:11:770734: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x2f2ecb43 vlan 0 vlan_tpid 0
02:04:11:770748: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:770764: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x06d7 dscp CS0 ecn NON_ECN
    fragment id 0xdbc1, flags DONT_FRAGMENT
  TCP: 34432 -> 6443
    seq. 0xb14e12e3 ack 0x48881b59
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:770771: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8680 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34432 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:770778: error-drop
  rx:host-eth0
02:04:11:770779: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 349

02:04:11:770734: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 94 snaplen 94 mac 66 net 80
      sec 0x5f35c656 nsec 0x2f2f3a39 vlan 0 vlan_tpid 0
02:04:11:770748: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:770760: error-drop
  rx:host-eth0
02:04:11:770769: drop
  ethernet-input: l3 mac mismatch

Packet 350

02:04:11:770734: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x2f2f843b vlan 0 vlan_tpid 0
02:04:11:770748: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:770764: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x06d6 dscp CS0 ecn NON_ECN
    fragment id 0xdbc2, flags DONT_FRAGMENT
  TCP: 34432 -> 6443
    seq. 0xb14e12e3 ack 0x48881b75
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:770771: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8680 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34432 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:770778: error-drop
  rx:host-eth0
02:04:11:770779: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 351

02:04:11:770734: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 102 snaplen 102 mac 66 net 80
      sec 0x5f35c656 nsec 0x2f2ffc6d vlan 0 vlan_tpid 0
02:04:11:770748: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:770760: error-drop
  rx:host-eth0
02:04:11:770769: drop
  ethernet-input: l3 mac mismatch

Packet 352

02:04:11:770734: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x2f304834 vlan 0 vlan_tpid 0
02:04:11:770748: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:770764: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x06d5 dscp CS0 ecn NON_ECN
    fragment id 0xdbc3, flags DONT_FRAGMENT
  TCP: 34432 -> 6443
    seq. 0xb14e12e3 ack 0x48881b99
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:770771: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8680 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34432 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:770778: error-drop
  rx:host-eth0
02:04:11:770779: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 353

02:04:11:771855: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c656 nsec 0x2f372dcb vlan 0 vlan_tpid 0
02:04:11:771864: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:771871: error-drop
  rx:host-eth0
02:04:11:771876: drop
  ethernet-input: l3 mac mismatch

Packet 354

02:04:11:771855: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x2f37d952 vlan 0 vlan_tpid 0
02:04:11:771864: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:771873: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x06d4 dscp CS0 ecn NON_ECN
    fragment id 0xdbc4, flags DONT_FRAGMENT
  TCP: 34432 -> 6443
    seq. 0xb14e12e3 ack 0x48881bb1
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:771878: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8680 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34432 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:771882: error-drop
  rx:host-eth0
02:04:11:771883: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 355

02:04:11:771855: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x2f38b695 vlan 0 vlan_tpid 0
02:04:11:771864: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:771871: error-drop
  rx:host-eth0
02:04:11:771876: drop
  ethernet-input: l3 mac mismatch

Packet 356

02:04:11:801531: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 305 snaplen 305 mac 66 net 80
      sec 0x5f35c656 nsec 0x30f462f5 vlan 0 vlan_tpid 0
02:04:11:801544: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:801554: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 291, checksum 0x5b55 dscp CS0 ecn NON_ECN
    fragment id 0x8654, flags DONT_FRAGMENT
  TCP: 34462 -> 6443
    seq. 0x986f147b ack 0x8fc39975
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 502, checksum 0x0000
02:04:11:801561: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b869e 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34462 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:11:801570: error-drop
  rx:host-eth0
02:04:11:801571: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 357

02:04:11:801531: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x30f4eacc vlan 0 vlan_tpid 0
02:04:11:801544: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:801558: error-drop
  rx:host-eth0
02:04:11:801567: drop
  ethernet-input: l3 mac mismatch

Packet 358

02:04:11:807025: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 1647 snaplen 1647 mac 66 net 80
      sec 0x5f35c656 nsec 0x31571c28 vlan 0 vlan_tpid 0
02:04:11:807034: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:807041: error-drop
  rx:host-eth0
02:04:11:807049: drop
  ethernet-input: l3 mac mismatch

Packet 359

02:04:11:807025: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x3157a316 vlan 0 vlan_tpid 0
02:04:11:807034: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:807043: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x5c43 dscp CS0 ecn NON_ECN
    fragment id 0x8655, flags DONT_FRAGMENT
  TCP: 34462 -> 6443
    seq. 0x986f156a ack 0x8fc39fa2
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:807050: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b869e 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34462 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:807057: error-drop
  rx:host-eth0
02:04:11:807057: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 360

02:04:11:807025: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x315b35c2 vlan 0 vlan_tpid 0
02:04:11:807034: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:807043: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x497a dscp CS0 ecn NON_ECN
    fragment id 0x991e, flags DONT_FRAGMENT
  TCP: 34434 -> 6443
    seq. 0x813c2428 ack 0xdd005c43
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:807050: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8682 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34434 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:807057: error-drop
  rx:host-eth0
02:04:11:807057: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 361

02:04:11:815565: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x31d56516 vlan 0 vlan_tpid 0
02:04:11:815572: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:815575: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x06d3 dscp CS0 ecn NON_ECN
    fragment id 0xdbc5, flags DONT_FRAGMENT
  TCP: 34432 -> 6443
    seq. 0xb14e12e3 ack 0x48881bb2
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:815579: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8680 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34432 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:815584: error-drop
  rx:host-eth0
02:04:11:815585: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 362

02:04:11:823376: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c656 nsec 0x324e60d8 vlan 0 vlan_tpid 0
02:04:11:823389: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:823400: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 76, checksum 0x4961 dscp CS0 ecn NON_ECN
    fragment id 0x991f, flags DONT_FRAGMENT
  TCP: 34434 -> 6443
    seq. 0x813c2428 ack 0xdd005c43
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:823409: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8682 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34434 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:11:823419: error-drop
  rx:host-eth0
02:04:11:823420: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 363

02:04:11:823376: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 74 snaplen 74 mac 66 net 80
      sec 0x5f35c656 nsec 0x324e5f74 vlan 0 vlan_tpid 0
02:04:11:823389: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:823400: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 60, checksum 0xd8aa dscp CS0 ecn NON_ECN
    fragment id 0x09e6, flags DONT_FRAGMENT
  TCP: 34466 -> 6443
    seq. 0xb208646b ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 64240, checksum 0x0000
02:04:11:823409: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86a2 0302ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34466 -> 6443 tcp flags (valid) 02 rsvd 0
02:04:11:823419: error-drop
  rx:host-eth0
02:04:11:823420: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 364

02:04:11:823376: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000001 len 54 snaplen 54 mac 66 net 80
      sec 0x5f35c656 nsec 0x324edcf2 vlan 0 vlan_tpid 0
02:04:11:823389: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:823406: error-drop
  rx:host-eth0
02:04:11:823417: drop
  ethernet-input: l3 mac mismatch

Packet 365

02:04:11:823376: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 74 snaplen 74 mac 66 net 80
      sec 0x5f35c656 nsec 0x324f2610 vlan 0 vlan_tpid 0
02:04:11:823389: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:823406: error-drop
  rx:host-eth0
02:04:11:823417: drop
  ethernet-input: l3 mac mismatch

Packet 366

02:04:11:823376: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x324fad0f vlan 0 vlan_tpid 0
02:04:11:823389: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:823400: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xd8b1 dscp CS0 ecn NON_ECN
    fragment id 0x09e7, flags DONT_FRAGMENT
  TCP: 34466 -> 6443
    seq. 0xb208646c ack 0xbdb7c442
    flags 0x10 ACK, tcp header: 32 bytes
    window 502, checksum 0x0000
02:04:11:823409: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86a2 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34466 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:823419: error-drop
  rx:host-eth0
02:04:11:823420: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 367

02:04:11:835903: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 318 snaplen 318 mac 66 net 80
      sec 0x5f35c656 nsec 0x330bbdc7 vlan 0 vlan_tpid 0
02:04:11:835915: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:835924: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 304, checksum 0x05d6 dscp CS0 ecn NON_ECN
    fragment id 0xdbc6, flags DONT_FRAGMENT
  TCP: 34432 -> 6443
    seq. 0xb14e12e3 ack 0x48881bb2
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:835930: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8680 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34432 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:11:835938: error-drop
  rx:host-eth0
02:04:11:835939: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 368

02:04:11:835903: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000001 len 54 snaplen 54 mac 66 net 80
      sec 0x5f35c656 nsec 0x330c2dcc vlan 0 vlan_tpid 0
02:04:11:835915: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:835928: error-drop
  rx:host-eth0
02:04:11:835936: drop
  ethernet-input: l3 mac mismatch

Packet 369

02:04:11:838073: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 74 snaplen 74 mac 66 net 80
      sec 0x5f35c656 nsec 0x332d0e55 vlan 0 vlan_tpid 0
02:04:11:838083: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:838090: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 60, checksum 0x4e4c dscp CS0 ecn NON_ECN
    fragment id 0x9444, flags DONT_FRAGMENT
  TCP: 34472 -> 6443
    seq. 0xb5967dec ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 64240, checksum 0x0000
02:04:11:838096: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86a8 0302ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34472 -> 6443 tcp flags (valid) 02 rsvd 0
02:04:11:838102: error-drop
  rx:host-eth0
02:04:11:838103: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 370

02:04:11:838073: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 74 snaplen 74 mac 66 net 80
      sec 0x5f35c656 nsec 0x332d913e vlan 0 vlan_tpid 0
02:04:11:838083: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:838094: error-drop
  rx:host-eth0
02:04:11:838100: drop
  ethernet-input: l3 mac mismatch

Packet 371

02:04:11:838073: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x332df1a5 vlan 0 vlan_tpid 0
02:04:11:838083: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:838090: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x4e53 dscp CS0 ecn NON_ECN
    fragment id 0x9445, flags DONT_FRAGMENT
  TCP: 34472 -> 6443
    seq. 0xb5967ded ack 0xa5e3a57c
    flags 0x10 ACK, tcp header: 32 bytes
    window 502, checksum 0x0000
02:04:11:838096: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86a8 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34472 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:838102: error-drop
  rx:host-eth0
02:04:11:838103: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 372

02:04:11:883667: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 305 snaplen 305 mac 66 net 80
      sec 0x5f35c656 nsec 0x35e8f902 vlan 0 vlan_tpid 0
02:04:11:883677: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:883683: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 291, checksum 0xd7c1 dscp CS0 ecn NON_ECN
    fragment id 0x09e8, flags DONT_FRAGMENT
  TCP: 34466 -> 6443
    seq. 0xb208646c ack 0xbdb7c442
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 502, checksum 0x0000
02:04:11:883689: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86a2 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34466 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:11:883696: error-drop
  rx:host-eth0
02:04:11:883697: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 373

02:04:11:883667: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x35e95943 vlan 0 vlan_tpid 0
02:04:11:883677: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:883687: error-drop
  rx:host-eth0
02:04:11:883694: drop
  ethernet-input: l3 mac mismatch

Packet 374

02:04:11:887416: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 1647 snaplen 1647 mac 66 net 80
      sec 0x5f35c656 nsec 0x361d1e1e vlan 0 vlan_tpid 0
02:04:11:887522: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:887528: error-drop
  rx:host-eth0
02:04:11:887536: drop
  ethernet-input: l3 mac mismatch

Packet 375

02:04:11:887416: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x361d971c vlan 0 vlan_tpid 0
02:04:11:887522: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:887531: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xd8af dscp CS0 ecn NON_ECN
    fragment id 0x09e9, flags DONT_FRAGMENT
  TCP: 34466 -> 6443
    seq. 0xb208655b ack 0xbdb7ca6f
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:887538: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86a2 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34466 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:887543: error-drop
  rx:host-eth0
02:04:11:887544: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 376

02:04:11:889914: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 1720 snaplen 1720 mac 66 net 80
      sec 0x5f35c656 nsec 0x364aa502 vlan 0 vlan_tpid 0
02:04:11:889924: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:889931: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 1706, checksum 0x55cc dscp CS0 ecn NON_ECN
    fragment id 0x8656, flags DONT_FRAGMENT
  TCP: 34462 -> 6443
    seq. 0x986f156a ack 0x8fc39fa2
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:889936: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b869e 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34462 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:11:889943: error-drop
  rx:host-eth0
02:04:11:889943: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 377

02:04:11:889914: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x364b042a vlan 0 vlan_tpid 0
02:04:11:889924: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:889935: error-drop
  rx:host-eth0
02:04:11:889941: drop
  ethernet-input: l3 mac mismatch

Packet 378

02:04:11:895960: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 305 snaplen 305 mac 66 net 80
      sec 0x5f35c656 nsec 0x3695c63c vlan 0 vlan_tpid 0
02:04:11:895968: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:895976: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 291, checksum 0x4d63 dscp CS0 ecn NON_ECN
    fragment id 0x9446, flags DONT_FRAGMENT
  TCP: 34472 -> 6443
    seq. 0xb5967ded ack 0xa5e3a57c
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 502, checksum 0x0000
02:04:11:895982: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86a8 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34472 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:11:895990: error-drop
  rx:host-eth0
02:04:11:895990: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 379

02:04:11:895960: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x36960f05 vlan 0 vlan_tpid 0
02:04:11:895968: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:895980: error-drop
  rx:host-eth0
02:04:11:895988: drop
  ethernet-input: l3 mac mismatch

Packet 380

02:04:11:898178: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 1647 snaplen 1647 mac 66 net 80
      sec 0x5f35c656 nsec 0x36c03a49 vlan 0 vlan_tpid 0
02:04:11:898185: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:898189: error-drop
  rx:host-eth0
02:04:11:898194: drop
  ethernet-input: l3 mac mismatch

Packet 381

02:04:11:898178: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x36c0860c vlan 0 vlan_tpid 0
02:04:11:898185: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:898191: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x4e51 dscp CS0 ecn NON_ECN
    fragment id 0x9447, flags DONT_FRAGMENT
  TCP: 34472 -> 6443
    seq. 0xb5967edc ack 0xa5e3aba9
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:898195: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86a8 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34472 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:898199: error-drop
  rx:host-eth0
02:04:11:898199: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 382

02:04:11:903558: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 247 snaplen 247 mac 66 net 80
      sec 0x5f35c656 nsec 0x3719d457 vlan 0 vlan_tpid 0
02:04:11:903568: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:903575: error-drop
  rx:host-eth0
02:04:11:903582: drop
  ethernet-input: l3 mac mismatch

Packet 383

02:04:11:903558: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x371a3af7 vlan 0 vlan_tpid 0
02:04:11:903568: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:903578: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x5c40 dscp CS0 ecn NON_ECN
    fragment id 0x8658, flags DONT_FRAGMENT
  TCP: 34462 -> 6443
    seq. 0x986f1be0 ack 0x8fc3a057
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:903584: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b869e 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34462 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:903588: error-drop
  rx:host-eth0
02:04:11:903589: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 384

02:04:11:961639: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 1720 snaplen 1720 mac 66 net 80
      sec 0x5f35c656 nsec 0x3a71f88a vlan 0 vlan_tpid 0
02:04:11:961651: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:961660: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 1706, checksum 0xd238 dscp CS0 ecn NON_ECN
    fragment id 0x09ea, flags DONT_FRAGMENT
  TCP: 34466 -> 6443
    seq. 0xb208655b ack 0xbdb7ca6f
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:961669: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86a2 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34466 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:11:961679: error-drop
  rx:host-eth0
02:04:11:961680: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 385

02:04:11:961639: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x3a724be9 vlan 0 vlan_tpid 0
02:04:11:961651: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:961666: error-drop
  rx:host-eth0
02:04:11:961676: drop
  ethernet-input: l3 mac mismatch

Packet 386

02:04:11:978073: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 247 snaplen 247 mac 66 net 80
      sec 0x5f35c656 nsec 0x3b7c6205 vlan 0 vlan_tpid 0
02:04:11:978083: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:978095: error-drop
  rx:host-eth0
02:04:11:978102: drop
  ethernet-input: l3 mac mismatch

Packet 387

02:04:11:978073: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x3b7cd534 vlan 0 vlan_tpid 0
02:04:11:978083: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:978090: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xd8ac dscp CS0 ecn NON_ECN
    fragment id 0x09ec, flags DONT_FRAGMENT
  TCP: 34466 -> 6443
    seq. 0xb2086bd1 ack 0xbdb7cb24
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:978097: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86a2 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34466 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:978105: error-drop
  rx:host-eth0
02:04:11:978105: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 388

02:04:11:978073: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 291 snaplen 291 mac 66 net 80
      sec 0x5f35c656 nsec 0x3b8b8236 vlan 0 vlan_tpid 0
02:04:11:978083: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:978090: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 277, checksum 0x5b5e dscp CS0 ecn NON_ECN
    fragment id 0x8659, flags DONT_FRAGMENT
  TCP: 34462 -> 6443
    seq. 0x986f1be0 ack 0x8fc3a057
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:978097: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b869e 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34462 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:11:978105: error-drop
  rx:host-eth0
02:04:11:978105: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 389

02:04:11:978073: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x3b8ba443 vlan 0 vlan_tpid 0
02:04:11:978083: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:978095: error-drop
  rx:host-eth0
02:04:11:978102: drop
  ethernet-input: l3 mac mismatch

Packet 390

02:04:11:979196: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c656 nsec 0x3b92608f vlan 0 vlan_tpid 0
02:04:11:979203: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:979210: error-drop
  rx:host-eth0
02:04:11:979215: drop
  ethernet-input: l3 mac mismatch

Packet 391

02:04:11:979196: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x3b92ab22 vlan 0 vlan_tpid 0
02:04:11:979203: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:979208: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x5c3e dscp CS0 ecn NON_ECN
    fragment id 0x865a, flags DONT_FRAGMENT
  TCP: 34462 -> 6443
    seq. 0x986f1cc1 ack 0x8fc3a06f
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:979211: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b869e 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34462 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:979216: error-drop
  rx:host-eth0
02:04:11:979216: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 392

02:04:11:979196: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 114 snaplen 114 mac 66 net 80
      sec 0x5f35c656 nsec 0x3b92f32b vlan 0 vlan_tpid 0
02:04:11:979203: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:979210: error-drop
  rx:host-eth0
02:04:11:979215: drop
  ethernet-input: l3 mac mismatch

Packet 393

02:04:11:979196: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c656 nsec 0x3b93065a vlan 0 vlan_tpid 0
02:04:11:979203: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:979208: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x5c3d dscp CS0 ecn NON_ECN
    fragment id 0x865b, flags DONT_FRAGMENT
  TCP: 34462 -> 6443
    seq. 0x986f1cc1 ack 0x8fc3a09f
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:979211: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b869e 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34462 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:979216: error-drop
  rx:host-eth0
02:04:11:979216: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 394

02:04:11:980283: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0xcb2df vlan 0 vlan_tpid 0
02:04:11:980289: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:980295: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xbfb2 dscp CS0 ecn NON_ECN
    fragment id 0x22e6, flags DONT_FRAGMENT
  TCP: 34382 -> 6443
    seq. 0x7770a30d ack 0x9c417002
    flags 0x11 FIN ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:980298: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b864e 0311ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34382 -> 6443 tcp flags (valid) 11 rsvd 0
02:04:11:980301: error-drop
  rx:host-eth0
02:04:11:980302: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 395

02:04:11:980283: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000001 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0xcef02 vlan 0 vlan_tpid 0
02:04:11:980289: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:980293: error-drop
  rx:host-eth0
02:04:11:980297: drop
  ethernet-input: l3 mac mismatch

Packet 396

02:04:11:980283: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 1715 snaplen 1715 mac 66 net 80
      sec 0x5f35c657 nsec 0xd9855 vlan 0 vlan_tpid 0
02:04:11:980289: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:980295: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 1701, checksum 0x47df dscp CS0 ecn NON_ECN
    fragment id 0x9448, flags DONT_FRAGMENT
  TCP: 34472 -> 6443
    seq. 0xb5967edc ack 0xa5e3aba9
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:980298: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86a8 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34472 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:11:980301: error-drop
  rx:host-eth0
02:04:11:980302: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 397

02:04:11:980283: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0xdd24f vlan 0 vlan_tpid 0
02:04:11:980289: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:980293: error-drop
  rx:host-eth0
02:04:11:980297: drop
  ethernet-input: l3 mac mismatch

Packet 398

02:04:11:989933: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 247 snaplen 247 mac 66 net 80
      sec 0x5f35c657 nsec 0x97d9f2 vlan 0 vlan_tpid 0
02:04:11:989941: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:11:989948: error-drop
  rx:host-eth0
02:04:11:989953: drop
  ethernet-input: l3 mac mismatch

Packet 399

02:04:11:989933: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x9837a4 vlan 0 vlan_tpid 0
02:04:11:989941: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:11:989950: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x4e4e dscp CS0 ecn NON_ECN
    fragment id 0x944a, flags DONT_FRAGMENT
  TCP: 34472 -> 6443
    seq. 0xb596854d ack 0xa5e3ac5e
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:11:989955: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86a8 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34472 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:11:989961: error-drop
  rx:host-eth0
02:04:11:989962: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 400

02:04:12:045531: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 275 snaplen 275 mac 66 net 80
      sec 0x5f35c657 nsec 0x3f343cd vlan 0 vlan_tpid 0
02:04:12:045543: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:045552: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 261, checksum 0x5b6b dscp CS0 ecn NON_ECN
    fragment id 0x865c, flags DONT_FRAGMENT
  TCP: 34462 -> 6443
    seq. 0x986f1cc1 ack 0x8fc3a09f
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:045559: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b869e 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34462 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:12:045569: error-drop
  rx:host-eth0
02:04:12:045570: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 401

02:04:12:045531: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 291 snaplen 291 mac 66 net 80
      sec 0x5f35c657 nsec 0x3f428f8 vlan 0 vlan_tpid 0
02:04:12:045543: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:045552: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 277, checksum 0x4d6c dscp CS0 ecn NON_ECN
    fragment id 0x944b, flags DONT_FRAGMENT
  TCP: 34472 -> 6443
    seq. 0xb596854d ack 0xa5e3ac5e
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:045559: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86a8 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34472 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:12:045569: error-drop
  rx:host-eth0
02:04:12:045570: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 402

02:04:12:045531: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x3f45765 vlan 0 vlan_tpid 0
02:04:12:045543: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:045557: error-drop
  rx:host-eth0
02:04:12:045566: drop
  ethernet-input: l3 mac mismatch

Packet 403

02:04:12:045531: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 291 snaplen 291 mac 66 net 80
      sec 0x5f35c657 nsec 0x3f4a139 vlan 0 vlan_tpid 0
02:04:12:045543: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:045552: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 277, checksum 0xd7ca dscp CS0 ecn NON_ECN
    fragment id 0x09ed, flags DONT_FRAGMENT
  TCP: 34466 -> 6443
    seq. 0xb2086bd1 ack 0xbdb7cb24
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:045559: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86a2 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34466 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:12:045569: error-drop
  rx:host-eth0
02:04:12:045570: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 404

02:04:12:045531: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x3f4fa13 vlan 0 vlan_tpid 0
02:04:12:045543: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:045557: error-drop
  rx:host-eth0
02:04:12:045566: drop
  ethernet-input: l3 mac mismatch

Packet 405

02:04:12:049429: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 100 snaplen 100 mac 66 net 80
      sec 0x5f35c657 nsec 0x427fc56 vlan 0 vlan_tpid 0
02:04:12:049469: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:049484: error-drop
  rx:host-eth0
02:04:12:049494: drop
  ethernet-input: l3 mac mismatch

Packet 406

02:04:12:049429: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x42851a2 vlan 0 vlan_tpid 0
02:04:12:049469: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:049479: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x4e4c dscp CS0 ecn NON_ECN
    fragment id 0x944c, flags DONT_FRAGMENT
  TCP: 34472 -> 6443
    seq. 0xb596862e ack 0xa5e3ac80
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:049486: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86a8 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34472 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:049498: error-drop
  rx:host-eth0
02:04:12:049499: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 407

02:04:12:049429: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 104 snaplen 104 mac 66 net 80
      sec 0x5f35c657 nsec 0x429ac38 vlan 0 vlan_tpid 0
02:04:12:049469: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:049484: error-drop
  rx:host-eth0
02:04:12:049494: drop
  ethernet-input: l3 mac mismatch

Packet 408

02:04:12:049429: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x429ddd2 vlan 0 vlan_tpid 0
02:04:12:049469: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:049479: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x4e4b dscp CS0 ecn NON_ECN
    fragment id 0x944d, flags DONT_FRAGMENT
  TCP: 34472 -> 6443
    seq. 0xb596862e ack 0xa5e3aca6
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:049486: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86a8 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34472 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:049498: error-drop
  rx:host-eth0
02:04:12:049499: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 409

02:04:12:049429: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c657 nsec 0x4302819 vlan 0 vlan_tpid 0
02:04:12:049469: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:049484: error-drop
  rx:host-eth0
02:04:12:049494: drop
  ethernet-input: l3 mac mismatch

Packet 410

02:04:12:049429: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x4305d0d vlan 0 vlan_tpid 0
02:04:12:049469: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:049479: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xd8aa dscp CS0 ecn NON_ECN
    fragment id 0x09ee, flags DONT_FRAGMENT
  TCP: 34466 -> 6443
    seq. 0xb2086cb2 ack 0xbdb7cb3c
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:049486: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86a2 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34466 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:049498: error-drop
  rx:host-eth0
02:04:12:049499: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 411

02:04:12:049429: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 96 snaplen 96 mac 66 net 80
      sec 0x5f35c657 nsec 0x4309ad8 vlan 0 vlan_tpid 0
02:04:12:049469: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:049484: error-drop
  rx:host-eth0
02:04:12:049494: drop
  ethernet-input: l3 mac mismatch

Packet 412

02:04:12:049429: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 114 snaplen 114 mac 66 net 80
      sec 0x5f35c657 nsec 0x430d904 vlan 0 vlan_tpid 0
02:04:12:049469: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:049484: error-drop
  rx:host-eth0
02:04:12:049494: drop
  ethernet-input: l3 mac mismatch

Packet 413

02:04:12:049429: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x430d9b5 vlan 0 vlan_tpid 0
02:04:12:049469: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:049479: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x5c3b dscp CS0 ecn NON_ECN
    fragment id 0x865d, flags DONT_FRAGMENT
  TCP: 34462 -> 6443
    seq. 0x986f1d92 ack 0x8fc3a0bd
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:049486: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b869e 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34462 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:049498: error-drop
  rx:host-eth0
02:04:12:049499: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 414

02:04:12:049429: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x430fd39 vlan 0 vlan_tpid 0
02:04:12:049469: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:049479: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xd8a9 dscp CS0 ecn NON_ECN
    fragment id 0x09ef, flags DONT_FRAGMENT
  TCP: 34466 -> 6443
    seq. 0xb2086cb2 ack 0xbdb7cb6c
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:049486: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86a2 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34466 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:049498: error-drop
  rx:host-eth0
02:04:12:049499: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 415

02:04:12:049429: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 100 snaplen 100 mac 66 net 80
      sec 0x5f35c657 nsec 0x4315507 vlan 0 vlan_tpid 0
02:04:12:049469: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:049484: error-drop
  rx:host-eth0
02:04:12:049494: drop
  ethernet-input: l3 mac mismatch

Packet 416

02:04:12:049429: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x4317a99 vlan 0 vlan_tpid 0
02:04:12:049469: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:049479: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x5c3a dscp CS0 ecn NON_ECN
    fragment id 0x865e, flags DONT_FRAGMENT
  TCP: 34462 -> 6443
    seq. 0x986f1d92 ack 0x8fc3a0df
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:049486: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b869e 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34462 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:049498: error-drop
  rx:host-eth0
02:04:12:049499: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 417

02:04:12:107559: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 275 snaplen 275 mac 66 net 80
      sec 0x5f35c657 nsec 0x7a40ff2 vlan 0 vlan_tpid 0
02:04:12:107574: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:107582: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 261, checksum 0xd7d7 dscp CS0 ecn NON_ECN
    fragment id 0x09f0, flags DONT_FRAGMENT
  TCP: 34466 -> 6443
    seq. 0xb2086cb2 ack 0xbdb7cb6c
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:107590: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86a2 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34466 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:12:107599: error-drop
  rx:host-eth0
02:04:12:107602: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 418

02:04:12:107559: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 274 snaplen 274 mac 66 net 80
      sec 0x5f35c657 nsec 0x7a4679b vlan 0 vlan_tpid 0
02:04:12:107574: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:107582: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 260, checksum 0x5b69 dscp CS0 ecn NON_ECN
    fragment id 0x865f, flags DONT_FRAGMENT
  TCP: 34462 -> 6443
    seq. 0x986f1d92 ack 0x8fc3a0df
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:107590: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b869e 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34462 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:12:107599: error-drop
  rx:host-eth0
02:04:12:107602: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 419

02:04:12:107559: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 275 snaplen 275 mac 66 net 80
      sec 0x5f35c657 nsec 0x7a52ad5 vlan 0 vlan_tpid 0
02:04:12:107574: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:107582: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 261, checksum 0x4d79 dscp CS0 ecn NON_ECN
    fragment id 0x944e, flags DONT_FRAGMENT
  TCP: 34472 -> 6443
    seq. 0xb596862e ack 0xa5e3aca6
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:107590: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86a8 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34472 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:12:107599: error-drop
  rx:host-eth0
02:04:12:107602: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 420

02:04:12:108717: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 108 snaplen 108 mac 66 net 80
      sec 0x5f35c657 nsec 0x7b54516 vlan 0 vlan_tpid 0
02:04:12:108754: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:108761: error-drop
  rx:host-eth0
02:04:12:108766: drop
  ethernet-input: l3 mac mismatch

Packet 421

02:04:12:108717: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x7b5b569 vlan 0 vlan_tpid 0
02:04:12:108754: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:108764: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x4e49 dscp CS0 ecn NON_ECN
    fragment id 0x944f, flags DONT_FRAGMENT
  TCP: 34472 -> 6443
    seq. 0xb59686ff ack 0xa5e3acd0
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:108768: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86a8 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34472 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:108772: error-drop
  rx:host-eth0
02:04:12:108773: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 422

02:04:12:108717: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c657 nsec 0x7b76e21 vlan 0 vlan_tpid 0
02:04:12:108754: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:108761: error-drop
  rx:host-eth0
02:04:12:108766: drop
  ethernet-input: l3 mac mismatch

Packet 423

02:04:12:108717: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x7b7c596 vlan 0 vlan_tpid 0
02:04:12:108754: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:108764: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x5c38 dscp CS0 ecn NON_ECN
    fragment id 0x8660, flags DONT_FRAGMENT
  TCP: 34462 -> 6443
    seq. 0x986f1e62 ack 0x8fc3a0f9
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:108768: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b869e 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34462 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:108772: error-drop
  rx:host-eth0
02:04:12:108773: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 424

02:04:12:109872: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c657 nsec 0x7be306a vlan 0 vlan_tpid 0
02:04:12:109882: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:109890: error-drop
  rx:host-eth0
02:04:12:109897: drop
  ethernet-input: l3 mac mismatch

Packet 425

02:04:12:109872: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x7be8198 vlan 0 vlan_tpid 0
02:04:12:109882: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:109893: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x5c37 dscp CS0 ecn NON_ECN
    fragment id 0x8661, flags DONT_FRAGMENT
  TCP: 34462 -> 6443
    seq. 0x986f1e62 ack 0x8fc3a113
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:109899: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b869e 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34462 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:109905: error-drop
  rx:host-eth0
02:04:12:109905: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 426

02:04:12:109872: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 100 snaplen 100 mac 66 net 80
      sec 0x5f35c657 nsec 0x7bf6eb6 vlan 0 vlan_tpid 0
02:04:12:109882: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:109890: error-drop
  rx:host-eth0
02:04:12:109897: drop
  ethernet-input: l3 mac mismatch

Packet 427

02:04:12:109872: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x7bfaa6e vlan 0 vlan_tpid 0
02:04:12:109882: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:109893: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x5c36 dscp CS0 ecn NON_ECN
    fragment id 0x8662, flags DONT_FRAGMENT
  TCP: 34462 -> 6443
    seq. 0x986f1e62 ack 0x8fc3a135
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:109899: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b869e 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34462 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:109905: error-drop
  rx:host-eth0
02:04:12:109905: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 428

02:04:12:113239: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 108 snaplen 108 mac 66 net 80
      sec 0x5f35c657 nsec 0x7f7635a vlan 0 vlan_tpid 0
02:04:12:113252: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:113261: error-drop
  rx:host-eth0
02:04:12:113270: drop
  ethernet-input: l3 mac mismatch

Packet 429

02:04:12:113239: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x7f80043 vlan 0 vlan_tpid 0
02:04:12:113252: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:113266: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xd8a7 dscp CS0 ecn NON_ECN
    fragment id 0x09f1, flags DONT_FRAGMENT
  TCP: 34466 -> 6443
    seq. 0xb2086d83 ack 0xbdb7cb96
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:113273: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86a2 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34466 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:113281: error-drop
  rx:host-eth0
02:04:12:113283: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 430

02:04:12:142733: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 96 snaplen 96 mac 66 net 80
      sec 0x5f35c657 nsec 0x9baa853 vlan 0 vlan_tpid 0
02:04:12:142742: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:142748: error-drop
  rx:host-eth0
02:04:12:142752: drop
  ethernet-input: l3 mac mismatch

Packet 431

02:04:12:142733: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x9bb04c3 vlan 0 vlan_tpid 0
02:04:12:142742: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:142750: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x5c35 dscp CS0 ecn NON_ECN
    fragment id 0x8663, flags DONT_FRAGMENT
  TCP: 34462 -> 6443
    seq. 0x986f1e62 ack 0x8fc3a153
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:142754: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b869e 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34462 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:142759: error-drop
  rx:host-eth0
02:04:12:142760: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 432

02:04:12:143862: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 96 snaplen 96 mac 66 net 80
      sec 0x5f35c657 nsec 0x9d06916 vlan 0 vlan_tpid 0
02:04:12:144077: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:144089: error-drop
  rx:host-eth0
02:04:12:144098: drop
  ethernet-input: l3 mac mismatch

Packet 433

02:04:12:143862: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x9d0b3cc vlan 0 vlan_tpid 0
02:04:12:144077: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:144094: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x5c34 dscp CS0 ecn NON_ECN
    fragment id 0x8664, flags DONT_FRAGMENT
  TCP: 34462 -> 6443
    seq. 0x986f1e62 ack 0x8fc3a171
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:144122: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b869e 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34462 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:144129: error-drop
  rx:host-eth0
02:04:12:144130: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 434

02:04:12:143862: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 140 snaplen 140 mac 66 net 80
      sec 0x5f35c657 nsec 0x9d10e72 vlan 0 vlan_tpid 0
02:04:12:144077: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:144089: error-drop
  rx:host-eth0
02:04:12:144098: drop
  ethernet-input: l3 mac mismatch

Packet 435

02:04:12:143862: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x9d179e7 vlan 0 vlan_tpid 0
02:04:12:144077: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:144094: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x5c33 dscp CS0 ecn NON_ECN
    fragment id 0x8665, flags DONT_FRAGMENT
  TCP: 34462 -> 6443
    seq. 0x986f1e62 ack 0x8fc3a1bb
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:144122: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b869e 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34462 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:144129: error-drop
  rx:host-eth0
02:04:12:144130: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 436

02:04:12:143862: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 98 snaplen 98 mac 66 net 80
      sec 0x5f35c657 nsec 0x9d1805d vlan 0 vlan_tpid 0
02:04:12:144077: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:144089: error-drop
  rx:host-eth0
02:04:12:144098: drop
  ethernet-input: l3 mac mismatch

Packet 437

02:04:12:143862: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 96 snaplen 96 mac 66 net 80
      sec 0x5f35c657 nsec 0x9d1b9ce vlan 0 vlan_tpid 0
02:04:12:144077: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:144089: error-drop
  rx:host-eth0
02:04:12:144098: drop
  ethernet-input: l3 mac mismatch

Packet 438

02:04:12:143862: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 96 snaplen 96 mac 66 net 80
      sec 0x5f35c657 nsec 0x9d1e90e vlan 0 vlan_tpid 0
02:04:12:144077: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:144089: error-drop
  rx:host-eth0
02:04:12:144098: drop
  ethernet-input: l3 mac mismatch

Packet 439

02:04:12:143862: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x9d21061 vlan 0 vlan_tpid 0
02:04:12:144077: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:144094: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x5c32 dscp CS0 ecn NON_ECN
    fragment id 0x8666, flags DONT_FRAGMENT
  TCP: 34462 -> 6443
    seq. 0x986f1e62 ack 0x8fc3a217
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:144122: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b869e 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34462 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:144129: error-drop
  rx:host-eth0
02:04:12:144130: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 440

02:04:12:143862: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c657 nsec 0x9d21509 vlan 0 vlan_tpid 0
02:04:12:144077: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:144089: error-drop
  rx:host-eth0
02:04:12:144098: drop
  ethernet-input: l3 mac mismatch

Packet 441

02:04:12:143862: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x9d2637f vlan 0 vlan_tpid 0
02:04:12:144077: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:144094: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x5c31 dscp CS0 ecn NON_ECN
    fragment id 0x8667, flags DONT_FRAGMENT
  TCP: 34462 -> 6443
    seq. 0x986f1e62 ack 0x8fc3a231
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:144122: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b869e 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34462 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:144129: error-drop
  rx:host-eth0
02:04:12:144130: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 442

02:04:12:143862: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c657 nsec 0x9d27e88 vlan 0 vlan_tpid 0
02:04:12:144077: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:144089: error-drop
  rx:host-eth0
02:04:12:144098: drop
  ethernet-input: l3 mac mismatch

Packet 443

02:04:12:143862: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x9d2a650 vlan 0 vlan_tpid 0
02:04:12:144077: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:144094: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x5c30 dscp CS0 ecn NON_ECN
    fragment id 0x8668, flags DONT_FRAGMENT
  TCP: 34462 -> 6443
    seq. 0x986f1e62 ack 0x8fc3a249
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:144122: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b869e 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34462 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:144129: error-drop
  rx:host-eth0
02:04:12:144130: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 444

02:04:12:143862: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x9d2ca4a vlan 0 vlan_tpid 0
02:04:12:144077: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:144089: error-drop
  rx:host-eth0
02:04:12:144098: drop
  ethernet-input: l3 mac mismatch

Packet 445

02:04:12:167344: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 274 snaplen 274 mac 66 net 80
      sec 0x5f35c657 nsec 0xb065fd0 vlan 0 vlan_tpid 0
02:04:12:167358: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:167370: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 260, checksum 0x4d78 dscp CS0 ecn NON_ECN
    fragment id 0x9450, flags DONT_FRAGMENT
  TCP: 34472 -> 6443
    seq. 0xb59686ff ack 0xa5e3acd0
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:167379: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86a8 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34472 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:12:167390: error-drop
  rx:host-eth0
02:04:12:167390: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 446

02:04:12:167344: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c657 nsec 0xb111214 vlan 0 vlan_tpid 0
02:04:12:167358: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:167377: error-drop
  rx:host-eth0
02:04:12:167387: drop
  ethernet-input: l3 mac mismatch

Packet 447

02:04:12:167344: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0xb116898 vlan 0 vlan_tpid 0
02:04:12:167358: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:167370: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x4e47 dscp CS0 ecn NON_ECN
    fragment id 0x9451, flags DONT_FRAGMENT
  TCP: 34472 -> 6443
    seq. 0xb59687cf ack 0xa5e3acea
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:167379: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86a8 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34472 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:167390: error-drop
  rx:host-eth0
02:04:12:167390: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 448

02:04:12:167344: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 104 snaplen 104 mac 66 net 80
      sec 0x5f35c657 nsec 0xb1211b6 vlan 0 vlan_tpid 0
02:04:12:167358: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:167377: error-drop
  rx:host-eth0
02:04:12:167387: drop
  ethernet-input: l3 mac mismatch

Packet 449

02:04:12:167344: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0xb12317d vlan 0 vlan_tpid 0
02:04:12:167358: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:167370: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x4e46 dscp CS0 ecn NON_ECN
    fragment id 0x9452, flags DONT_FRAGMENT
  TCP: 34472 -> 6443
    seq. 0xb59687cf ack 0xa5e3ad10
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:167379: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86a8 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34472 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:167390: error-drop
  rx:host-eth0
02:04:12:167390: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 450

02:04:12:168471: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 166 snaplen 166 mac 66 net 80
      sec 0x5f35c657 nsec 0xb3ed900 vlan 0 vlan_tpid 0
02:04:12:168479: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:168484: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 152, checksum 0xd842 dscp CS0 ecn NON_ECN
    fragment id 0x09f2, flags DONT_FRAGMENT
  TCP: 34466 -> 6443
    seq. 0xb2086d83 ack 0xbdb7cb96
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:168489: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86a2 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34466 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:12:168495: error-drop
  rx:host-eth0
02:04:12:168496: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 451

02:04:12:172313: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 174 snaplen 174 mac 66 net 80
      sec 0x5f35c657 nsec 0xb76788d vlan 0 vlan_tpid 0
02:04:12:172324: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:172337: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 160, checksum 0xd839 dscp CS0 ecn NON_ECN
    fragment id 0x09f3, flags DONT_FRAGMENT
  TCP: 34466 -> 6443
    seq. 0xb2086de7 ack 0xbdb7cb96
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:172345: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86a2 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34466 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:12:172353: error-drop
  rx:host-eth0
02:04:12:172354: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 452

02:04:12:172313: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0xb78922d vlan 0 vlan_tpid 0
02:04:12:172324: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:172334: error-drop
  rx:host-eth0
02:04:12:172342: drop
  ethernet-input: l3 mac mismatch

Packet 453

02:04:12:172313: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c657 nsec 0xb7f2d7e vlan 0 vlan_tpid 0
02:04:12:172324: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:172334: error-drop
  rx:host-eth0
02:04:12:172342: drop
  ethernet-input: l3 mac mismatch

Packet 454

02:04:12:172313: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0xb7f6872 vlan 0 vlan_tpid 0
02:04:12:172324: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:172337: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xd8a4 dscp CS0 ecn NON_ECN
    fragment id 0x09f4, flags DONT_FRAGMENT
  TCP: 34466 -> 6443
    seq. 0xb2086e53 ack 0xbdb7cbb0
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:172345: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86a2 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34466 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:172353: error-drop
  rx:host-eth0
02:04:12:172354: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 455

02:04:12:172313: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 104 snaplen 104 mac 66 net 80
      sec 0x5f35c657 nsec 0xb8148c5 vlan 0 vlan_tpid 0
02:04:12:172324: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:172334: error-drop
  rx:host-eth0
02:04:12:172342: drop
  ethernet-input: l3 mac mismatch

Packet 456

02:04:12:172313: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0xb8176d4 vlan 0 vlan_tpid 0
02:04:12:172324: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:172337: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xd8a3 dscp CS0 ecn NON_ECN
    fragment id 0x09f5, flags DONT_FRAGMENT
  TCP: 34466 -> 6443
    seq. 0xb2086e53 ack 0xbdb7cbd6
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:172345: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86a2 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34466 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:172353: error-drop
  rx:host-eth0
02:04:12:172354: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 457

02:04:12:191449: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0xca3d97d vlan 0 vlan_tpid 0
02:04:12:191459: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:191464: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x5c2f dscp CS0 ecn NON_ECN
    fragment id 0x8669, flags DONT_FRAGMENT
  TCP: 34462 -> 6443
    seq. 0x986f1e62 ack 0x8fc3a24a
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:191467: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b869e 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34462 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:191473: error-drop
  rx:host-eth0
02:04:12:191475: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 458

02:04:12:203681: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 74 snaplen 74 mac 66 net 80
      sec 0x5f35c657 nsec 0xd4b39a8 vlan 0 vlan_tpid 0
02:04:12:203689: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:203697: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 60, checksum 0x197f dscp CS0 ecn NON_ECN
    fragment id 0xc911, flags DONT_FRAGMENT
  TCP: 34502 -> 6443
    seq. 0x071853c5 ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 64240, checksum 0x0000
02:04:12:203701: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86c6 0302ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34502 -> 6443 tcp flags (valid) 02 rsvd 0
02:04:12:203706: error-drop
  rx:host-eth0
02:04:12:203707: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 459

02:04:12:203681: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 74 snaplen 74 mac 66 net 80
      sec 0x5f35c657 nsec 0xd4bcd7a vlan 0 vlan_tpid 0
02:04:12:203689: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:203696: error-drop
  rx:host-eth0
02:04:12:203700: drop
  ethernet-input: l3 mac mismatch

Packet 460

02:04:12:203681: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0xd4c22e8 vlan 0 vlan_tpid 0
02:04:12:203689: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:203697: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x1986 dscp CS0 ecn NON_ECN
    fragment id 0xc912, flags DONT_FRAGMENT
  TCP: 34502 -> 6443
    seq. 0x071853c6 ack 0x85ba5441
    flags 0x10 ACK, tcp header: 32 bytes
    window 502, checksum 0x0000
02:04:12:203701: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86c6 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34502 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:203706: error-drop
  rx:host-eth0
02:04:12:203707: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 461

02:04:12:203681: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 468 snaplen 468 mac 66 net 80
      sec 0x5f35c657 nsec 0xd4d7267 vlan 0 vlan_tpid 0
02:04:12:203689: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:203697: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 454, checksum 0x5a9c dscp CS0 ecn NON_ECN
    fragment id 0x866a, flags DONT_FRAGMENT
  TCP: 34462 -> 6443
    seq. 0x986f1e62 ack 0x8fc3a24a
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:203701: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b869e 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34462 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:12:203706: error-drop
  rx:host-eth0
02:04:12:203707: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 462

02:04:12:203681: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000001 len 54 snaplen 54 mac 66 net 80
      sec 0x5f35c657 nsec 0xd4da4f7 vlan 0 vlan_tpid 0
02:04:12:203689: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:203696: error-drop
  rx:host-eth0
02:04:12:203700: drop
  ethernet-input: l3 mac mismatch

Packet 463

02:04:12:204898: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c657 nsec 0xd6dcb54 vlan 0 vlan_tpid 0
02:04:12:204910: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:204923: error-drop
  rx:host-eth0
02:04:12:204930: drop
  ethernet-input: l3 mac mismatch

Packet 464

02:04:12:204898: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0xd6e1e02 vlan 0 vlan_tpid 0
02:04:12:204910: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:204918: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x4e45 dscp CS0 ecn NON_ECN
    fragment id 0x9453, flags DONT_FRAGMENT
  TCP: 34472 -> 6443
    seq. 0xb59687cf ack 0xa5e3ad2a
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:204925: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86a8 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34472 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:204932: error-drop
  rx:host-eth0
02:04:12:204933: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 465

02:04:12:204898: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c657 nsec 0xd724cc4 vlan 0 vlan_tpid 0
02:04:12:204910: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:204923: error-drop
  rx:host-eth0
02:04:12:204930: drop
  ethernet-input: l3 mac mismatch

Packet 466

02:04:12:204898: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0xd7280f8 vlan 0 vlan_tpid 0
02:04:12:204910: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:204918: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x4e44 dscp CS0 ecn NON_ECN
    fragment id 0x9454, flags DONT_FRAGMENT
  TCP: 34472 -> 6443
    seq. 0xb59687cf ack 0xa5e3ad44
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:204925: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86a8 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34472 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:204932: error-drop
  rx:host-eth0
02:04:12:204933: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 467

02:04:12:207482: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 96 snaplen 96 mac 66 net 80
      sec 0x5f35c657 nsec 0xd9375c9 vlan 0 vlan_tpid 0
02:04:12:207498: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:207512: error-drop
  rx:host-eth0
02:04:12:207568: drop
  ethernet-input: l3 mac mismatch

Packet 468

02:04:12:207482: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0xd93b6a0 vlan 0 vlan_tpid 0
02:04:12:207498: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:207515: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x4e43 dscp CS0 ecn NON_ECN
    fragment id 0x9455, flags DONT_FRAGMENT
  TCP: 34472 -> 6443
    seq. 0xb59687cf ack 0xa5e3ad62
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:207571: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86a8 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34472 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:207578: error-drop
  rx:host-eth0
02:04:12:207579: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 469

02:04:12:207482: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 134 snaplen 134 mac 66 net 80
      sec 0x5f35c657 nsec 0xd940f28 vlan 0 vlan_tpid 0
02:04:12:207498: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:207512: error-drop
  rx:host-eth0
02:04:12:207568: drop
  ethernet-input: l3 mac mismatch

Packet 470

02:04:12:207482: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 94 snaplen 94 mac 66 net 80
      sec 0x5f35c657 nsec 0xd943c39 vlan 0 vlan_tpid 0
02:04:12:207498: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:207512: error-drop
  rx:host-eth0
02:04:12:207568: drop
  ethernet-input: l3 mac mismatch

Packet 471

02:04:12:207482: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0xd944417 vlan 0 vlan_tpid 0
02:04:12:207498: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:207515: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x4e42 dscp CS0 ecn NON_ECN
    fragment id 0x9456, flags DONT_FRAGMENT
  TCP: 34472 -> 6443
    seq. 0xb59687cf ack 0xa5e3ada6
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:207571: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86a8 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34472 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:207578: error-drop
  rx:host-eth0
02:04:12:207579: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 472

02:04:12:207482: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 102 snaplen 102 mac 66 net 80
      sec 0x5f35c657 nsec 0xd946d81 vlan 0 vlan_tpid 0
02:04:12:207498: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:207512: error-drop
  rx:host-eth0
02:04:12:207568: drop
  ethernet-input: l3 mac mismatch

Packet 473

02:04:12:207482: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 96 snaplen 96 mac 66 net 80
      sec 0x5f35c657 nsec 0xd949a73 vlan 0 vlan_tpid 0
02:04:12:207498: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:207512: error-drop
  rx:host-eth0
02:04:12:207568: drop
  ethernet-input: l3 mac mismatch

Packet 474

02:04:12:207482: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 96 snaplen 96 mac 66 net 80
      sec 0x5f35c657 nsec 0xd94c6ee vlan 0 vlan_tpid 0
02:04:12:207498: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:207512: error-drop
  rx:host-eth0
02:04:12:207568: drop
  ethernet-input: l3 mac mismatch

Packet 475

02:04:12:207482: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0xd94f399 vlan 0 vlan_tpid 0
02:04:12:207498: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:207515: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x4e41 dscp CS0 ecn NON_ECN
    fragment id 0x9457, flags DONT_FRAGMENT
  TCP: 34472 -> 6443
    seq. 0xb59687cf ack 0xa5e3ae22
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:207571: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86a8 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34472 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:207578: error-drop
  rx:host-eth0
02:04:12:207579: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 476

02:04:12:207482: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c657 nsec 0xd9535cd vlan 0 vlan_tpid 0
02:04:12:207498: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:207512: error-drop
  rx:host-eth0
02:04:12:207568: drop
  ethernet-input: l3 mac mismatch

Packet 477

02:04:12:207482: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0xd9558de vlan 0 vlan_tpid 0
02:04:12:207498: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:207515: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x4e40 dscp CS0 ecn NON_ECN
    fragment id 0x9458, flags DONT_FRAGMENT
  TCP: 34472 -> 6443
    seq. 0xb59687cf ack 0xa5e3ae3a
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:207571: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86a8 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34472 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:207578: error-drop
  rx:host-eth0
02:04:12:207579: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 478

02:04:12:207482: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0xd959c32 vlan 0 vlan_tpid 0
02:04:12:207498: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:207512: error-drop
  rx:host-eth0
02:04:12:207568: drop
  ethernet-input: l3 mac mismatch

Packet 479

02:04:12:211864: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 96 snaplen 96 mac 66 net 80
      sec 0x5f35c657 nsec 0xdd3bf8a vlan 0 vlan_tpid 0
02:04:12:211873: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:211880: error-drop
  rx:host-eth0
02:04:12:211976: drop
  ethernet-input: l3 mac mismatch

Packet 480

02:04:12:211864: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0xdd440ec vlan 0 vlan_tpid 0
02:04:12:211873: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:211973: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xd8a2 dscp CS0 ecn NON_ECN
    fragment id 0x09f6, flags DONT_FRAGMENT
  TCP: 34466 -> 6443
    seq. 0xb2086e53 ack 0xbdb7cbf4
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:211977: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86a2 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34466 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:211983: error-drop
  rx:host-eth0
02:04:12:211983: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 481

02:04:12:213055: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 130 snaplen 130 mac 66 net 80
      sec 0x5f35c657 nsec 0xde4eaf9 vlan 0 vlan_tpid 0
02:04:12:213068: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:213078: error-drop
  rx:host-eth0
02:04:12:213084: drop
  ethernet-input: l3 mac mismatch

Packet 482

02:04:12:213055: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0xde534de vlan 0 vlan_tpid 0
02:04:12:213068: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:213080: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xd8a1 dscp CS0 ecn NON_ECN
    fragment id 0x09f7, flags DONT_FRAGMENT
  TCP: 34466 -> 6443
    seq. 0xb2086e53 ack 0xbdb7cc34
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:213086: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86a2 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34466 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:213092: error-drop
  rx:host-eth0
02:04:12:213093: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 483

02:04:12:213055: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 120 snaplen 120 mac 66 net 80
      sec 0x5f35c657 nsec 0xde9bb65 vlan 0 vlan_tpid 0
02:04:12:213068: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:213078: error-drop
  rx:host-eth0
02:04:12:213084: drop
  ethernet-input: l3 mac mismatch

Packet 484

02:04:12:213055: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0xde9e293 vlan 0 vlan_tpid 0
02:04:12:213068: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:213080: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xd8a0 dscp CS0 ecn NON_ECN
    fragment id 0x09f8, flags DONT_FRAGMENT
  TCP: 34466 -> 6443
    seq. 0xb2086e53 ack 0xbdb7cc6a
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:213086: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86a2 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34466 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:213092: error-drop
  rx:host-eth0
02:04:12:213093: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 485

02:04:12:213055: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 104 snaplen 104 mac 66 net 80
      sec 0x5f35c657 nsec 0xdea1ef9 vlan 0 vlan_tpid 0
02:04:12:213068: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:213078: error-drop
  rx:host-eth0
02:04:12:213084: drop
  ethernet-input: l3 mac mismatch

Packet 486

02:04:12:213055: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c657 nsec 0xdea6f0d vlan 0 vlan_tpid 0
02:04:12:213068: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:213078: error-drop
  rx:host-eth0
02:04:12:213084: drop
  ethernet-input: l3 mac mismatch

Packet 487

02:04:12:213055: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0xdea6d32 vlan 0 vlan_tpid 0
02:04:12:213068: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:213080: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xd89f dscp CS0 ecn NON_ECN
    fragment id 0x09f9, flags DONT_FRAGMENT
  TCP: 34466 -> 6443
    seq. 0xb2086e53 ack 0xbdb7cc90
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:213086: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86a2 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34466 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:213092: error-drop
  rx:host-eth0
02:04:12:213093: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 488

02:04:12:213055: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0xdeabce9 vlan 0 vlan_tpid 0
02:04:12:213068: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:213078: error-drop
  rx:host-eth0
02:04:12:213084: drop
  ethernet-input: l3 mac mismatch

Packet 489

02:04:12:213055: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0xdeacfd6 vlan 0 vlan_tpid 0
02:04:12:213068: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:213080: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xd89e dscp CS0 ecn NON_ECN
    fragment id 0x09fa, flags DONT_FRAGMENT
  TCP: 34466 -> 6443
    seq. 0xb2086e53 ack 0xbdb7cca8
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:213086: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86a2 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34466 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:213092: error-drop
  rx:host-eth0
02:04:12:213093: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 490

02:04:12:247483: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0xffa825a vlan 0 vlan_tpid 0
02:04:12:247492: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:247497: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x4e3f dscp CS0 ecn NON_ECN
    fragment id 0x9459, flags DONT_FRAGMENT
  TCP: 34472 -> 6443
    seq. 0xb59687cf ack 0xa5e3ae3b
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:247502: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86a8 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34472 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:247506: error-drop
  rx:host-eth0
02:04:12:247507: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 491

02:04:12:259469: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 305 snaplen 305 mac 66 net 80
      sec 0x5f35c657 nsec 0x10a03ded vlan 0 vlan_tpid 0
02:04:12:259479: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:259485: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 291, checksum 0x1896 dscp CS0 ecn NON_ECN
    fragment id 0xc913, flags DONT_FRAGMENT
  TCP: 34502 -> 6443
    seq. 0x071853c6 ack 0x85ba5441
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 502, checksum 0x0000
02:04:12:259492: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86c6 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34502 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:12:259499: error-drop
  rx:host-eth0
02:04:12:259500: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 492

02:04:12:259469: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x10a0a7d9 vlan 0 vlan_tpid 0
02:04:12:259479: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:259490: error-drop
  rx:host-eth0
02:04:12:259497: drop
  ethernet-input: l3 mac mismatch

Packet 493

02:04:12:259469: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x10b15cb7 vlan 0 vlan_tpid 0
02:04:12:259479: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:259485: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xd89d dscp CS0 ecn NON_ECN
    fragment id 0x09fb, flags DONT_FRAGMENT
  TCP: 34466 -> 6443
    seq. 0xb2086e53 ack 0xbdb7cca9
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:259492: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86a2 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34466 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:259499: error-drop
  rx:host-eth0
02:04:12:259500: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 494

02:04:12:261836: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 1647 snaplen 1647 mac 66 net 80
      sec 0x5f35c657 nsec 0x10cd3411 vlan 0 vlan_tpid 0
02:04:12:261846: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:261853: error-drop
  rx:host-eth0
02:04:12:261858: drop
  ethernet-input: l3 mac mismatch

Packet 495

02:04:12:261836: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x10cd87ee vlan 0 vlan_tpid 0
02:04:12:261846: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:261855: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x1984 dscp CS0 ecn NON_ECN
    fragment id 0xc914, flags DONT_FRAGMENT
  TCP: 34502 -> 6443
    seq. 0x071854b5 ack 0x85ba5a6e
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:261859: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86c6 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34502 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:261864: error-drop
  rx:host-eth0
02:04:12:261864: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 496

02:04:12:261836: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c657 nsec 0x10d658c2 vlan 0 vlan_tpid 0
02:04:12:261846: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:261855: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 76, checksum 0x4e26 dscp CS0 ecn NON_ECN
    fragment id 0x945a, flags DONT_FRAGMENT
  TCP: 34472 -> 6443
    seq. 0xb59687cf ack 0xa5e3ae3b
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:261859: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86a8 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34472 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:12:261864: error-drop
  rx:host-eth0
02:04:12:261864: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 497

02:04:12:261836: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000001 len 54 snaplen 54 mac 66 net 80
      sec 0x5f35c657 nsec 0x10d69a04 vlan 0 vlan_tpid 0
02:04:12:261846: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:261853: error-drop
  rx:host-eth0
02:04:12:261858: drop
  ethernet-input: l3 mac mismatch

Packet 498

02:04:12:266832: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 74 snaplen 74 mac 66 net 80
      sec 0x5f35c657 nsec 0x11213ff0 vlan 0 vlan_tpid 0
02:04:12:266842: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:266850: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 60, checksum 0x27bd dscp CS0 ecn NON_ECN
    fragment id 0xbad3, flags DONT_FRAGMENT
  TCP: 34506 -> 6443
    seq. 0x4301aa10 ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 64240, checksum 0x0000
02:04:12:266856: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ca 0302ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34506 -> 6443 tcp flags (valid) 02 rsvd 0
02:04:12:266864: error-drop
  rx:host-eth0
02:04:12:266865: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 499

02:04:12:266832: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 74 snaplen 74 mac 66 net 80
      sec 0x5f35c657 nsec 0x1121cf6a vlan 0 vlan_tpid 0
02:04:12:266842: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:266855: error-drop
  rx:host-eth0
02:04:12:266861: drop
  ethernet-input: l3 mac mismatch

Packet 500

02:04:12:266832: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x112223f2 vlan 0 vlan_tpid 0
02:04:12:266842: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:266850: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x27c4 dscp CS0 ecn NON_ECN
    fragment id 0xbad4, flags DONT_FRAGMENT
  TCP: 34506 -> 6443
    seq. 0x4301aa11 ack 0x83c2928e
    flags 0x10 ACK, tcp header: 32 bytes
    window 502, checksum 0x0000
02:04:12:266856: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ca 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34506 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:266864: error-drop
  rx:host-eth0
02:04:12:266865: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 501

02:04:12:274513: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 468 snaplen 468 mac 66 net 80
      sec 0x5f35c657 nsec 0x117ecf08 vlan 0 vlan_tpid 0
02:04:12:274523: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:274533: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 454, checksum 0xd70a dscp CS0 ecn NON_ECN
    fragment id 0x09fc, flags DONT_FRAGMENT
  TCP: 34466 -> 6443
    seq. 0xb2086e53 ack 0xbdb7cca9
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:274540: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86a2 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34466 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:12:274546: error-drop
  rx:host-eth0
02:04:12:274547: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 502

02:04:12:274513: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000001 len 54 snaplen 54 mac 66 net 80
      sec 0x5f35c657 nsec 0x117f2860 vlan 0 vlan_tpid 0
02:04:12:274523: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:274530: error-drop
  rx:host-eth0
02:04:12:274537: drop
  ethernet-input: l3 mac mismatch

Packet 503

02:04:12:274513: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 74 snaplen 74 mac 66 net 80
      sec 0x5f35c657 nsec 0x11815a8b vlan 0 vlan_tpid 0
02:04:12:274523: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:274533: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 60, checksum 0xfab6 dscp CS0 ecn NON_ECN
    fragment id 0xe7d9, flags DONT_FRAGMENT
  TCP: 34510 -> 6443
    seq. 0x8fefeb26 ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 64240, checksum 0x0000
02:04:12:274540: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ce 0302ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34510 -> 6443 tcp flags (valid) 02 rsvd 0
02:04:12:274546: error-drop
  rx:host-eth0
02:04:12:274547: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 504

02:04:12:274513: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 74 snaplen 74 mac 66 net 80
      sec 0x5f35c657 nsec 0x1181c685 vlan 0 vlan_tpid 0
02:04:12:274523: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:274530: error-drop
  rx:host-eth0
02:04:12:274537: drop
  ethernet-input: l3 mac mismatch

Packet 505

02:04:12:274513: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x118205fa vlan 0 vlan_tpid 0
02:04:12:274523: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:274533: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xfabd dscp CS0 ecn NON_ECN
    fragment id 0xe7da, flags DONT_FRAGMENT
  TCP: 34510 -> 6443
    seq. 0x8fefeb27 ack 0x00e28a3c
    flags 0x10 ACK, tcp header: 32 bytes
    window 502, checksum 0x0000
02:04:12:274540: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ce 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34510 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:274546: error-drop
  rx:host-eth0
02:04:12:274547: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 506

02:04:12:330839: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 1727 snaplen 1727 mac 66 net 80
      sec 0x5f35c657 nsec 0x14e25b6d vlan 0 vlan_tpid 0
02:04:12:330851: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:330856: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 1713, checksum 0x1306 dscp CS0 ecn NON_ECN
    fragment id 0xc915, flags DONT_FRAGMENT
  TCP: 34502 -> 6443
    seq. 0x071854b5 ack 0x85ba5a6e
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:330861: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86c6 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34502 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:12:330868: error-drop
  rx:host-eth0
02:04:12:330868: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 507

02:04:12:330839: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x14e2b67c vlan 0 vlan_tpid 0
02:04:12:330851: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:330860: error-drop
  rx:host-eth0
02:04:12:330866: drop
  ethernet-input: l3 mac mismatch

Packet 508

02:04:12:331970: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 305 snaplen 305 mac 66 net 80
      sec 0x5f35c657 nsec 0x14f55ed5 vlan 0 vlan_tpid 0
02:04:12:331978: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:331984: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 291, checksum 0x26d4 dscp CS0 ecn NON_ECN
    fragment id 0xbad5, flags DONT_FRAGMENT
  TCP: 34506 -> 6443
    seq. 0x4301aa11 ack 0x83c2928e
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 502, checksum 0x0000
02:04:12:331989: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ca 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34506 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:12:331994: error-drop
  rx:host-eth0
02:04:12:331994: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 509

02:04:12:331970: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x14f5c31d vlan 0 vlan_tpid 0
02:04:12:331978: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:331987: error-drop
  rx:host-eth0
02:04:12:331992: drop
  ethernet-input: l3 mac mismatch

Packet 510

02:04:12:334195: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 305 snaplen 305 mac 66 net 80
      sec 0x5f35c657 nsec 0x151730bd vlan 0 vlan_tpid 0
02:04:12:334203: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:334208: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 291, checksum 0xf9cd dscp CS0 ecn NON_ECN
    fragment id 0xe7db, flags DONT_FRAGMENT
  TCP: 34510 -> 6443
    seq. 0x8fefeb27 ack 0x00e28a3c
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 502, checksum 0x0000
02:04:12:334213: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ce 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34510 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:12:334219: error-drop
  rx:host-eth0
02:04:12:334219: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 511

02:04:12:334195: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x1517add3 vlan 0 vlan_tpid 0
02:04:12:334203: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:334212: error-drop
  rx:host-eth0
02:04:12:334217: drop
  ethernet-input: l3 mac mismatch

Packet 512

02:04:12:336336: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 1647 snaplen 1647 mac 66 net 80
      sec 0x5f35c657 nsec 0x15400bd2 vlan 0 vlan_tpid 0
02:04:12:336344: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:336350: error-drop
  rx:host-eth0
02:04:12:336355: drop
  ethernet-input: l3 mac mismatch

Packet 513

02:04:12:336336: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x1540873f vlan 0 vlan_tpid 0
02:04:12:336344: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:336352: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x27c2 dscp CS0 ecn NON_ECN
    fragment id 0xbad6, flags DONT_FRAGMENT
  TCP: 34506 -> 6443
    seq. 0x4301ab00 ack 0x83c298bb
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:336357: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ca 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34506 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:336407: error-drop
  rx:host-eth0
02:04:12:336407: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 514

02:04:12:338571: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 1647 snaplen 1647 mac 66 net 80
      sec 0x5f35c657 nsec 0x155b34c4 vlan 0 vlan_tpid 0
02:04:12:338580: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:338585: error-drop
  rx:host-eth0
02:04:12:338591: drop
  ethernet-input: l3 mac mismatch

Packet 515

02:04:12:338571: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x155ba01f vlan 0 vlan_tpid 0
02:04:12:338580: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:338587: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xfabb dscp CS0 ecn NON_ECN
    fragment id 0xe7dc, flags DONT_FRAGMENT
  TCP: 34510 -> 6443
    seq. 0x8fefec16 ack 0x00e29069
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:338592: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ce 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34510 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:338596: error-drop
  rx:host-eth0
02:04:12:338597: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 516

02:04:12:353995: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 247 snaplen 247 mac 66 net 80
      sec 0x5f35c657 nsec 0x16511b7f vlan 0 vlan_tpid 0
02:04:12:354002: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:354008: error-drop
  rx:host-eth0
02:04:12:354012: drop
  ethernet-input: l3 mac mismatch

Packet 517

02:04:12:353995: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x1651931d vlan 0 vlan_tpid 0
02:04:12:354002: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:354010: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x1981 dscp CS0 ecn NON_ECN
    fragment id 0xc917, flags DONT_FRAGMENT
  TCP: 34502 -> 6443
    seq. 0x07185b32 ack 0x85ba5b23
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:354014: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86c6 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34502 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:354019: error-drop
  rx:host-eth0
02:04:12:354019: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 518

02:04:12:410711: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 291 snaplen 291 mac 66 net 80
      sec 0x5f35c657 nsec 0x19b036cf vlan 0 vlan_tpid 0
02:04:12:410724: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:410736: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 277, checksum 0x189f dscp CS0 ecn NON_ECN
    fragment id 0xc918, flags DONT_FRAGMENT
  TCP: 34502 -> 6443
    seq. 0x07185b32 ack 0x85ba5b23
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:410743: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86c6 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34502 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:12:410750: error-drop
  rx:host-eth0
02:04:12:410751: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 519

02:04:12:410711: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x19b07360 vlan 0 vlan_tpid 0
02:04:12:410724: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:410733: error-drop
  rx:host-eth0
02:04:12:410740: drop
  ethernet-input: l3 mac mismatch

Packet 520

02:04:12:410711: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 1727 snaplen 1727 mac 66 net 80
      sec 0x5f35c657 nsec 0x19b120a3 vlan 0 vlan_tpid 0
02:04:12:410724: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:410736: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 1713, checksum 0xf43d dscp CS0 ecn NON_ECN
    fragment id 0xe7dd, flags DONT_FRAGMENT
  TCP: 34510 -> 6443
    seq. 0x8fefec16 ack 0x00e29069
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:410743: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ce 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34510 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:12:410750: error-drop
  rx:host-eth0
02:04:12:410751: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 521

02:04:12:410711: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x19b1434b vlan 0 vlan_tpid 0
02:04:12:410724: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:410733: error-drop
  rx:host-eth0
02:04:12:410740: drop
  ethernet-input: l3 mac mismatch

Packet 522

02:04:12:410711: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 1722 snaplen 1722 mac 66 net 80
      sec 0x5f35c657 nsec 0x19b1516f vlan 0 vlan_tpid 0
02:04:12:410724: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:410736: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 1708, checksum 0x2149 dscp CS0 ecn NON_ECN
    fragment id 0xbad7, flags DONT_FRAGMENT
  TCP: 34506 -> 6443
    seq. 0x4301ab00 ack 0x83c298bb
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:410743: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ca 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34506 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:12:410750: error-drop
  rx:host-eth0
02:04:12:410751: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 523

02:04:12:410711: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x19b178da vlan 0 vlan_tpid 0
02:04:12:410724: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:410733: error-drop
  rx:host-eth0
02:04:12:410740: drop
  ethernet-input: l3 mac mismatch

Packet 524

02:04:12:411837: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c657 nsec 0x19bfaa12 vlan 0 vlan_tpid 0
02:04:12:411850: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:411865: error-drop
  rx:host-eth0
02:04:12:411873: drop
  ethernet-input: l3 mac mismatch

Packet 525

02:04:12:411837: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x19bffd19 vlan 0 vlan_tpid 0
02:04:12:411850: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:411859: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x197f dscp CS0 ecn NON_ECN
    fragment id 0xc919, flags DONT_FRAGMENT
  TCP: 34502 -> 6443
    seq. 0x07185c13 ack 0x85ba5b3b
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:411867: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86c6 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34502 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:411904: error-drop
  rx:host-eth0
02:04:12:411905: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 526

02:04:12:411837: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c657 nsec 0x19c196c6 vlan 0 vlan_tpid 0
02:04:12:411850: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:411865: error-drop
  rx:host-eth0
02:04:12:411873: drop
  ethernet-input: l3 mac mismatch

Packet 527

02:04:12:411837: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x19c1bcfa vlan 0 vlan_tpid 0
02:04:12:411850: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:411859: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x197e dscp CS0 ecn NON_ECN
    fragment id 0xc91a, flags DONT_FRAGMENT
  TCP: 34502 -> 6443
    seq. 0x07185c13 ack 0x85ba5b53
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:411867: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86c6 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34502 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:411904: error-drop
  rx:host-eth0
02:04:12:411905: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 528

02:04:12:411837: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c657 nsec 0x19c1f4f4 vlan 0 vlan_tpid 0
02:04:12:411850: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:411865: error-drop
  rx:host-eth0
02:04:12:411873: drop
  ethernet-input: l3 mac mismatch

Packet 529

02:04:12:411837: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x19c20ce9 vlan 0 vlan_tpid 0
02:04:12:411850: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:411859: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x197d dscp CS0 ecn NON_ECN
    fragment id 0xc91b, flags DONT_FRAGMENT
  TCP: 34502 -> 6443
    seq. 0x07185c13 ack 0x85ba5b6d
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:411867: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86c6 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34502 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:411904: error-drop
  rx:host-eth0
02:04:12:411905: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 530

02:04:12:411837: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c657 nsec 0x19c23a2e vlan 0 vlan_tpid 0
02:04:12:411850: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:411865: error-drop
  rx:host-eth0
02:04:12:411873: drop
  ethernet-input: l3 mac mismatch

Packet 531

02:04:12:411837: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x19c24fcd vlan 0 vlan_tpid 0
02:04:12:411850: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:411859: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x197c dscp CS0 ecn NON_ECN
    fragment id 0xc91c, flags DONT_FRAGMENT
  TCP: 34502 -> 6443
    seq. 0x07185c13 ack 0x85ba5b87
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:411867: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86c6 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34502 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:411904: error-drop
  rx:host-eth0
02:04:12:411905: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 532

02:04:12:411837: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 104 snaplen 104 mac 66 net 80
      sec 0x5f35c657 nsec 0x19c27b79 vlan 0 vlan_tpid 0
02:04:12:411850: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:411865: error-drop
  rx:host-eth0
02:04:12:411873: drop
  ethernet-input: l3 mac mismatch

Packet 533

02:04:12:411837: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x19c292be vlan 0 vlan_tpid 0
02:04:12:411850: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:411859: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x197b dscp CS0 ecn NON_ECN
    fragment id 0xc91d, flags DONT_FRAGMENT
  TCP: 34502 -> 6443
    seq. 0x07185c13 ack 0x85ba5bad
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:411867: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86c6 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34502 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:411904: error-drop
  rx:host-eth0
02:04:12:411905: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 534

02:04:12:432660: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 247 snaplen 247 mac 66 net 80
      sec 0x5f35c657 nsec 0x1aff4408 vlan 0 vlan_tpid 0
02:04:12:432669: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:432676: error-drop
  rx:host-eth0
02:04:12:432681: drop
  ethernet-input: l3 mac mismatch

Packet 535

02:04:12:432660: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x1affdcef vlan 0 vlan_tpid 0
02:04:12:432669: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:432678: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x27bf dscp CS0 ecn NON_ECN
    fragment id 0xbad9, flags DONT_FRAGMENT
  TCP: 34506 -> 6443
    seq. 0x4301b178 ack 0x83c29970
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:432684: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ca 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34506 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:432689: error-drop
  rx:host-eth0
02:04:12:432689: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 536

02:04:12:437089: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 247 snaplen 247 mac 66 net 80
      sec 0x5f35c657 nsec 0x1b125837 vlan 0 vlan_tpid 0
02:04:12:437098: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:437105: error-drop
  rx:host-eth0
02:04:12:437110: drop
  ethernet-input: l3 mac mismatch

Packet 537

02:04:12:437089: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x1b12da3a vlan 0 vlan_tpid 0
02:04:12:437098: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:437107: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xfab8 dscp CS0 ecn NON_ECN
    fragment id 0xe7df, flags DONT_FRAGMENT
  TCP: 34510 -> 6443
    seq. 0x8feff293 ack 0x00e2911e
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:437111: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ce 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34510 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:437116: error-drop
  rx:host-eth0
02:04:12:437116: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 538

02:04:12:472671: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c657 nsec 0x1d58c527 vlan 0 vlan_tpid 0
02:04:12:472679: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:472683: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 76, checksum 0x1962 dscp CS0 ecn NON_ECN
    fragment id 0xc91e, flags DONT_FRAGMENT
  TCP: 34502 -> 6443
    seq. 0x07185c13 ack 0x85ba5bad
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:472686: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86c6 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34502 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:12:472691: error-drop
  rx:host-eth0
02:04:12:472692: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 539

02:04:12:480726: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 251 snaplen 251 mac 66 net 80
      sec 0x5f35c657 nsec 0x1dd3de7e vlan 0 vlan_tpid 0
02:04:12:480739: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:480752: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 237, checksum 0x18c0 dscp CS0 ecn NON_ECN
    fragment id 0xc91f, flags DONT_FRAGMENT
  TCP: 34502 -> 6443
    seq. 0x07185c2b ack 0x85ba5bad
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:480761: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86c6 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34502 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:12:480784: error-drop
  rx:host-eth0
02:04:12:480784: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 540

02:04:12:480726: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x1dd53aab vlan 0 vlan_tpid 0
02:04:12:480739: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:480749: error-drop
  rx:host-eth0
02:04:12:480758: drop
  ethernet-input: l3 mac mismatch

Packet 541

02:04:12:480726: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c657 nsec 0x1ddeb428 vlan 0 vlan_tpid 0
02:04:12:480739: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:480749: error-drop
  rx:host-eth0
02:04:12:480758: drop
  ethernet-input: l3 mac mismatch

Packet 542

02:04:12:480726: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x1ddeeabb vlan 0 vlan_tpid 0
02:04:12:480739: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:480752: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x1978 dscp CS0 ecn NON_ECN
    fragment id 0xc920, flags DONT_FRAGMENT
  TCP: 34502 -> 6443
    seq. 0x07185ce4 ack 0x85ba5bc5
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:480761: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86c6 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34502 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:480784: error-drop
  rx:host-eth0
02:04:12:480784: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 543

02:04:12:480726: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c657 nsec 0x1ddf3577 vlan 0 vlan_tpid 0
02:04:12:480739: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:480749: error-drop
  rx:host-eth0
02:04:12:480758: drop
  ethernet-input: l3 mac mismatch

Packet 544

02:04:12:480726: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x1ddf50c9 vlan 0 vlan_tpid 0
02:04:12:480739: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:480752: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x1977 dscp CS0 ecn NON_ECN
    fragment id 0xc921, flags DONT_FRAGMENT
  TCP: 34502 -> 6443
    seq. 0x07185ce4 ack 0x85ba5bdd
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:480761: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86c6 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34502 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:480784: error-drop
  rx:host-eth0
02:04:12:480784: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 545

02:04:12:480726: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c657 nsec 0x1ddf7fdc vlan 0 vlan_tpid 0
02:04:12:480739: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:480749: error-drop
  rx:host-eth0
02:04:12:480758: drop
  ethernet-input: l3 mac mismatch

Packet 546

02:04:12:480726: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x1ddf979c vlan 0 vlan_tpid 0
02:04:12:480739: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:480752: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x1976 dscp CS0 ecn NON_ECN
    fragment id 0xc922, flags DONT_FRAGMENT
  TCP: 34502 -> 6443
    seq. 0x07185ce4 ack 0x85ba5bf7
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:480761: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86c6 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34502 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:480784: error-drop
  rx:host-eth0
02:04:12:480784: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 547

02:04:12:480726: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c657 nsec 0x1ddfc713 vlan 0 vlan_tpid 0
02:04:12:480739: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:480749: error-drop
  rx:host-eth0
02:04:12:480758: drop
  ethernet-input: l3 mac mismatch

Packet 548

02:04:12:480726: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x1ddfe068 vlan 0 vlan_tpid 0
02:04:12:480739: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:480752: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x1975 dscp CS0 ecn NON_ECN
    fragment id 0xc923, flags DONT_FRAGMENT
  TCP: 34502 -> 6443
    seq. 0x07185ce4 ack 0x85ba5c11
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:480761: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86c6 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34502 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:480784: error-drop
  rx:host-eth0
02:04:12:480784: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 549

02:04:12:480726: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 96 snaplen 96 mac 66 net 80
      sec 0x5f35c657 nsec 0x1de0100c vlan 0 vlan_tpid 0
02:04:12:480739: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:480749: error-drop
  rx:host-eth0
02:04:12:480758: drop
  ethernet-input: l3 mac mismatch

Packet 550

02:04:12:482090: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x1de0a008 vlan 0 vlan_tpid 0
02:04:12:482097: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:482102: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x1974 dscp CS0 ecn NON_ECN
    fragment id 0xc924, flags DONT_FRAGMENT
  TCP: 34502 -> 6443
    seq. 0x07185ce4 ack 0x85ba5c2f
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:482105: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86c6 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34502 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:482109: error-drop
  rx:host-eth0
02:04:12:482110: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 551

02:04:12:488126: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 291 snaplen 291 mac 66 net 80
      sec 0x5f35c657 nsec 0x1e4c56bb vlan 0 vlan_tpid 0
02:04:12:488135: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:488152: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 277, checksum 0x26dd dscp CS0 ecn NON_ECN
    fragment id 0xbada, flags DONT_FRAGMENT
  TCP: 34506 -> 6443
    seq. 0x4301b178 ack 0x83c29970
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:488157: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ca 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34506 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:12:488165: error-drop
  rx:host-eth0
02:04:12:488166: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 552

02:04:12:488126: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x1e4c95e8 vlan 0 vlan_tpid 0
02:04:12:488135: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:488156: error-drop
  rx:host-eth0
02:04:12:488163: drop
  ethernet-input: l3 mac mismatch

Packet 553

02:04:12:489235: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c657 nsec 0x1e5bacc7 vlan 0 vlan_tpid 0
02:04:12:489245: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:489258: error-drop
  rx:host-eth0
02:04:12:489264: drop
  ethernet-input: l3 mac mismatch

Packet 554

02:04:12:489235: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x1e5bf2c0 vlan 0 vlan_tpid 0
02:04:12:489245: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:489253: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x27bd dscp CS0 ecn NON_ECN
    fragment id 0xbadb, flags DONT_FRAGMENT
  TCP: 34506 -> 6443
    seq. 0x4301b259 ack 0x83c29988
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:489259: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ca 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34506 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:489267: error-drop
  rx:host-eth0
02:04:12:489267: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 555

02:04:12:489235: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c657 nsec 0x1e5c488e vlan 0 vlan_tpid 0
02:04:12:489245: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:489258: error-drop
  rx:host-eth0
02:04:12:489264: drop
  ethernet-input: l3 mac mismatch

Packet 556

02:04:12:489235: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x1e5c68e9 vlan 0 vlan_tpid 0
02:04:12:489245: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:489253: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x27bc dscp CS0 ecn NON_ECN
    fragment id 0xbadc, flags DONT_FRAGMENT
  TCP: 34506 -> 6443
    seq. 0x4301b259 ack 0x83c299a0
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:489259: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ca 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34506 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:489267: error-drop
  rx:host-eth0
02:04:12:489267: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 557

02:04:12:489235: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c657 nsec 0x1e5c9d89 vlan 0 vlan_tpid 0
02:04:12:489245: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:489258: error-drop
  rx:host-eth0
02:04:12:489264: drop
  ethernet-input: l3 mac mismatch

Packet 558

02:04:12:489235: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x1e5cb6c1 vlan 0 vlan_tpid 0
02:04:12:489245: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:489253: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x27bb dscp CS0 ecn NON_ECN
    fragment id 0xbadd, flags DONT_FRAGMENT
  TCP: 34506 -> 6443
    seq. 0x4301b259 ack 0x83c299ba
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:489259: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ca 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34506 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:489267: error-drop
  rx:host-eth0
02:04:12:489267: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 559

02:04:12:489235: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c657 nsec 0x1e5ce83d vlan 0 vlan_tpid 0
02:04:12:489245: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:489258: error-drop
  rx:host-eth0
02:04:12:489264: drop
  ethernet-input: l3 mac mismatch

Packet 560

02:04:12:489235: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x1e5d0020 vlan 0 vlan_tpid 0
02:04:12:489245: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:489253: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x27ba dscp CS0 ecn NON_ECN
    fragment id 0xbade, flags DONT_FRAGMENT
  TCP: 34506 -> 6443
    seq. 0x4301b259 ack 0x83c299d4
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:489259: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ca 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34506 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:489267: error-drop
  rx:host-eth0
02:04:12:489267: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 561

02:04:12:489235: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 104 snaplen 104 mac 66 net 80
      sec 0x5f35c657 nsec 0x1e5d31d2 vlan 0 vlan_tpid 0
02:04:12:489245: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:489258: error-drop
  rx:host-eth0
02:04:12:489264: drop
  ethernet-input: l3 mac mismatch

Packet 562

02:04:12:489235: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x1e5d4b06 vlan 0 vlan_tpid 0
02:04:12:489245: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:489253: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x27b9 dscp CS0 ecn NON_ECN
    fragment id 0xbadf, flags DONT_FRAGMENT
  TCP: 34506 -> 6443
    seq. 0x4301b259 ack 0x83c299fa
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:489259: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ca 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34506 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:489267: error-drop
  rx:host-eth0
02:04:12:489267: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 563

02:04:12:509601: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 291 snaplen 291 mac 66 net 80
      sec 0x5f35c657 nsec 0x1f87cb8f vlan 0 vlan_tpid 0
02:04:12:509611: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:509616: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 277, checksum 0xf9d6 dscp CS0 ecn NON_ECN
    fragment id 0xe7e0, flags DONT_FRAGMENT
  TCP: 34510 -> 6443
    seq. 0x8feff293 ack 0x00e2911e
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:509636: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ce 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34510 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:12:509643: error-drop
  rx:host-eth0
02:04:12:509643: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 564

02:04:12:509601: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x1f880d2b vlan 0 vlan_tpid 0
02:04:12:509611: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:509635: error-drop
  rx:host-eth0
02:04:12:509641: drop
  ethernet-input: l3 mac mismatch

Packet 565

02:04:12:510714: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c657 nsec 0x1f98ada1 vlan 0 vlan_tpid 0
02:04:12:510722: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:510732: error-drop
  rx:host-eth0
02:04:12:510738: drop
  ethernet-input: l3 mac mismatch

Packet 566

02:04:12:510714: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x1f98f6c4 vlan 0 vlan_tpid 0
02:04:12:510722: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:510728: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xfab6 dscp CS0 ecn NON_ECN
    fragment id 0xe7e1, flags DONT_FRAGMENT
  TCP: 34510 -> 6443
    seq. 0x8feff374 ack 0x00e29136
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:510733: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ce 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34510 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:510740: error-drop
  rx:host-eth0
02:04:12:510740: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 567

02:04:12:510714: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 114 snaplen 114 mac 66 net 80
      sec 0x5f35c657 nsec 0x1f995021 vlan 0 vlan_tpid 0
02:04:12:510722: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:510732: error-drop
  rx:host-eth0
02:04:12:510738: drop
  ethernet-input: l3 mac mismatch

Packet 568

02:04:12:510714: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x1f99711d vlan 0 vlan_tpid 0
02:04:12:510722: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:510728: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xfab5 dscp CS0 ecn NON_ECN
    fragment id 0xe7e2, flags DONT_FRAGMENT
  TCP: 34510 -> 6443
    seq. 0x8feff374 ack 0x00e29166
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:510733: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ce 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34510 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:510740: error-drop
  rx:host-eth0
02:04:12:510740: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 569

02:04:12:562865: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 275 snaplen 275 mac 66 net 80
      sec 0x5f35c657 nsec 0x22b64322 vlan 0 vlan_tpid 0
02:04:12:562873: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:562879: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 261, checksum 0x26e7 dscp CS0 ecn NON_ECN
    fragment id 0xbae0, flags DONT_FRAGMENT
  TCP: 34506 -> 6443
    seq. 0x4301b259 ack 0x83c299fa
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:562922: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ca 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34506 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:12:562927: error-drop
  rx:host-eth0
02:04:12:562929: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 570

02:04:12:563980: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c657 nsec 0x22c875b9 vlan 0 vlan_tpid 0
02:04:12:564004: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:564013: error-drop
  rx:host-eth0
02:04:12:564020: drop
  ethernet-input: l3 mac mismatch

Packet 571

02:04:12:563980: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x22c8c7f2 vlan 0 vlan_tpid 0
02:04:12:564004: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:564016: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x27b7 dscp CS0 ecn NON_ECN
    fragment id 0xbae1, flags DONT_FRAGMENT
  TCP: 34506 -> 6443
    seq. 0x4301b32a ack 0x83c29a12
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:564022: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ca 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34506 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:564029: error-drop
  rx:host-eth0
02:04:12:564030: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 572

02:04:12:563980: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c657 nsec 0x22c94477 vlan 0 vlan_tpid 0
02:04:12:564004: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:564013: error-drop
  rx:host-eth0
02:04:12:564020: drop
  ethernet-input: l3 mac mismatch

Packet 573

02:04:12:563980: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x22c960ff vlan 0 vlan_tpid 0
02:04:12:564004: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:564016: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x27b6 dscp CS0 ecn NON_ECN
    fragment id 0xbae2, flags DONT_FRAGMENT
  TCP: 34506 -> 6443
    seq. 0x4301b32a ack 0x83c29a2a
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:564022: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ca 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34506 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:564029: error-drop
  rx:host-eth0
02:04:12:564030: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 574

02:04:12:563980: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c657 nsec 0x22c98fc6 vlan 0 vlan_tpid 0
02:04:12:564004: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:564013: error-drop
  rx:host-eth0
02:04:12:564020: drop
  ethernet-input: l3 mac mismatch

Packet 575

02:04:12:563980: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x22c9a6a4 vlan 0 vlan_tpid 0
02:04:12:564004: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:564016: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x27b5 dscp CS0 ecn NON_ECN
    fragment id 0xbae3, flags DONT_FRAGMENT
  TCP: 34506 -> 6443
    seq. 0x4301b32a ack 0x83c29a44
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:564022: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ca 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34506 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:564029: error-drop
  rx:host-eth0
02:04:12:564030: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 576

02:04:12:563980: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 100 snaplen 100 mac 66 net 80
      sec 0x5f35c657 nsec 0x22c9d1dc vlan 0 vlan_tpid 0
02:04:12:564004: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:564013: error-drop
  rx:host-eth0
02:04:12:564020: drop
  ethernet-input: l3 mac mismatch

Packet 577

02:04:12:563980: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x22c9e800 vlan 0 vlan_tpid 0
02:04:12:564004: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:564016: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x27b4 dscp CS0 ecn NON_ECN
    fragment id 0xbae4, flags DONT_FRAGMENT
  TCP: 34506 -> 6443
    seq. 0x4301b32a ack 0x83c29a66
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:564022: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ca 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34506 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:564029: error-drop
  rx:host-eth0
02:04:12:564030: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 578

02:04:12:563980: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 274 snaplen 274 mac 66 net 80
      sec 0x5f35c657 nsec 0x22cd7c03 vlan 0 vlan_tpid 0
02:04:12:564004: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:564016: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 260, checksum 0x18a3 dscp CS0 ecn NON_ECN
    fragment id 0xc925, flags DONT_FRAGMENT
  TCP: 34502 -> 6443
    seq. 0x07185ce4 ack 0x85ba5c2f
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:564022: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86c6 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34502 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:12:564029: error-drop
  rx:host-eth0
02:04:12:564030: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 579

02:04:12:565257: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c657 nsec 0x22d5a74c vlan 0 vlan_tpid 0
02:04:12:565265: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:565272: error-drop
  rx:host-eth0
02:04:12:565278: drop
  ethernet-input: l3 mac mismatch

Packet 580

02:04:12:565257: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 104 snaplen 104 mac 66 net 80
      sec 0x5f35c657 nsec 0x22d60de8 vlan 0 vlan_tpid 0
02:04:12:565265: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:565272: error-drop
  rx:host-eth0
02:04:12:565278: drop
  ethernet-input: l3 mac mismatch

Packet 581

02:04:12:565257: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x22d71961 vlan 0 vlan_tpid 0
02:04:12:565265: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:565276: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x1972 dscp CS0 ecn NON_ECN
    fragment id 0xc926, flags DONT_FRAGMENT
  TCP: 34502 -> 6443
    seq. 0x07185db4 ack 0x85ba5c6f
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:565280: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86c6 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34502 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:565285: error-drop
  rx:host-eth0
02:04:12:565286: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 582

02:04:12:589598: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 275 snaplen 275 mac 66 net 80
      sec 0x5f35c657 nsec 0x245a5c7e vlan 0 vlan_tpid 0
02:04:12:589607: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:589612: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 261, checksum 0xf9e3 dscp CS0 ecn NON_ECN
    fragment id 0xe7e3, flags DONT_FRAGMENT
  TCP: 34510 -> 6443
    seq. 0x8feff374 ack 0x00e29166
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:589616: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ce 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34510 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:12:589645: error-drop
  rx:host-eth0
02:04:12:589646: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 583

02:04:12:590727: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c657 nsec 0x246477be vlan 0 vlan_tpid 0
02:04:12:590737: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:590744: error-drop
  rx:host-eth0
02:04:12:590749: drop
  ethernet-input: l3 mac mismatch

Packet 584

02:04:12:590727: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x2464b588 vlan 0 vlan_tpid 0
02:04:12:590737: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:590746: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xfab3 dscp CS0 ecn NON_ECN
    fragment id 0xe7e4, flags DONT_FRAGMENT
  TCP: 34510 -> 6443
    seq. 0x8feff445 ack 0x00e29180
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:590750: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ce 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34510 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:590755: error-drop
  rx:host-eth0
02:04:12:590756: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 585

02:04:12:590727: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 104 snaplen 104 mac 66 net 80
      sec 0x5f35c657 nsec 0x246525fc vlan 0 vlan_tpid 0
02:04:12:590737: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:590744: error-drop
  rx:host-eth0
02:04:12:590749: drop
  ethernet-input: l3 mac mismatch

Packet 586

02:04:12:590727: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x246540d9 vlan 0 vlan_tpid 0
02:04:12:590737: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:590746: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xfab2 dscp CS0 ecn NON_ECN
    fragment id 0xe7e5, flags DONT_FRAGMENT
  TCP: 34510 -> 6443
    seq. 0x8feff445 ack 0x00e291a6
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:590750: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ce 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34510 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:590755: error-drop
  rx:host-eth0
02:04:12:590756: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 587

02:04:12:617756: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c657 nsec 0x25f81810 vlan 0 vlan_tpid 0
02:04:12:617768: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:617777: error-drop
  rx:host-eth0
02:04:12:617783: drop
  ethernet-input: l3 mac mismatch

Packet 588

02:04:12:617756: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x25f90f44 vlan 0 vlan_tpid 0
02:04:12:617768: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:617779: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x1971 dscp CS0 ecn NON_ECN
    fragment id 0xc927, flags DONT_FRAGMENT
  TCP: 34502 -> 6443
    seq. 0x07185db4 ack 0x85ba5c89
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:617786: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86c6 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34502 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:617793: error-drop
  rx:host-eth0
02:04:12:617794: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 589

02:04:12:617756: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c657 nsec 0x2600fb03 vlan 0 vlan_tpid 0
02:04:12:617768: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:617777: error-drop
  rx:host-eth0
02:04:12:617783: drop
  ethernet-input: l3 mac mismatch

Packet 590

02:04:12:617756: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x26018bcd vlan 0 vlan_tpid 0
02:04:12:617768: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:617779: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x1970 dscp CS0 ecn NON_ECN
    fragment id 0xc928, flags DONT_FRAGMENT
  TCP: 34502 -> 6443
    seq. 0x07185db4 ack 0x85ba5ca3
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:617786: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86c6 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34502 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:617793: error-drop
  rx:host-eth0
02:04:12:617794: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 591

02:04:12:617756: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 138 snaplen 138 mac 66 net 80
      sec 0x5f35c657 nsec 0x2601b8c9 vlan 0 vlan_tpid 0
02:04:12:617768: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:617777: error-drop
  rx:host-eth0
02:04:12:617783: drop
  ethernet-input: l3 mac mismatch

Packet 592

02:04:12:617756: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 98 snaplen 98 mac 66 net 80
      sec 0x5f35c657 nsec 0x2601ede0 vlan 0 vlan_tpid 0
02:04:12:617768: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:617777: error-drop
  rx:host-eth0
02:04:12:617783: drop
  ethernet-input: l3 mac mismatch

Packet 593

02:04:12:617756: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 104 snaplen 104 mac 66 net 80
      sec 0x5f35c657 nsec 0x26021a43 vlan 0 vlan_tpid 0
02:04:12:617768: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:617777: error-drop
  rx:host-eth0
02:04:12:617783: drop
  ethernet-input: l3 mac mismatch

Packet 594

02:04:12:617756: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x260210fa vlan 0 vlan_tpid 0
02:04:12:617768: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:617779: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x196f dscp CS0 ecn NON_ECN
    fragment id 0xc929, flags DONT_FRAGMENT
  TCP: 34502 -> 6443
    seq. 0x07185db4 ack 0x85ba5d0b
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:617786: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86c6 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34502 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:617793: error-drop
  rx:host-eth0
02:04:12:617794: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 595

02:04:12:617756: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c657 nsec 0x2602456f vlan 0 vlan_tpid 0
02:04:12:617768: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:617777: error-drop
  rx:host-eth0
02:04:12:617783: drop
  ethernet-input: l3 mac mismatch

Packet 596

02:04:12:617756: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 96 snaplen 96 mac 66 net 80
      sec 0x5f35c657 nsec 0x26027222 vlan 0 vlan_tpid 0
02:04:12:617768: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:617777: error-drop
  rx:host-eth0
02:04:12:617783: drop
  ethernet-input: l3 mac mismatch

Packet 597

02:04:12:617756: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x26027f68 vlan 0 vlan_tpid 0
02:04:12:617768: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:617779: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x196e dscp CS0 ecn NON_ECN
    fragment id 0xc92a, flags DONT_FRAGMENT
  TCP: 34502 -> 6443
    seq. 0x07185db4 ack 0x85ba5d49
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:617786: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86c6 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34502 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:617793: error-drop
  rx:host-eth0
02:04:12:617794: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 598

02:04:12:617756: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c657 nsec 0x2602a03b vlan 0 vlan_tpid 0
02:04:12:617768: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:617777: error-drop
  rx:host-eth0
02:04:12:617783: drop
  ethernet-input: l3 mac mismatch

Packet 599

02:04:12:617756: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x2602d0d7 vlan 0 vlan_tpid 0
02:04:12:617768: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:617779: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x196d dscp CS0 ecn NON_ECN
    fragment id 0xc92b, flags DONT_FRAGMENT
  TCP: 34502 -> 6443
    seq. 0x07185db4 ack 0x85ba5d81
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:617786: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86c6 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34502 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:617793: error-drop
  rx:host-eth0
02:04:12:617794: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 600

02:04:12:617756: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c657 nsec 0x26030ee1 vlan 0 vlan_tpid 0
02:04:12:617768: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:617777: error-drop
  rx:host-eth0
02:04:12:617783: drop
  ethernet-input: l3 mac mismatch

Packet 601

02:04:12:617756: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x2603382c vlan 0 vlan_tpid 0
02:04:12:617768: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:617779: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x196c dscp CS0 ecn NON_ECN
    fragment id 0xc92c, flags DONT_FRAGMENT
  TCP: 34502 -> 6443
    seq. 0x07185db4 ack 0x85ba5d99
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:617786: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86c6 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34502 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:617793: error-drop
  rx:host-eth0
02:04:12:617794: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 602

02:04:12:617756: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x26036119 vlan 0 vlan_tpid 0
02:04:12:617768: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:617777: error-drop
  rx:host-eth0
02:04:12:617783: drop
  ethernet-input: l3 mac mismatch

Packet 603

02:04:12:633383: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 274 snaplen 274 mac 66 net 80
      sec 0x5f35c657 nsec 0x26ee0262 vlan 0 vlan_tpid 0
02:04:12:633391: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:633396: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 260, checksum 0x26e3 dscp CS0 ecn NON_ECN
    fragment id 0xbae5, flags DONT_FRAGMENT
  TCP: 34506 -> 6443
    seq. 0x4301b32a ack 0x83c29a66
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:633400: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ca 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34506 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:12:633405: error-drop
  rx:host-eth0
02:04:12:633406: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 604

02:04:12:634464: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 96 snaplen 96 mac 66 net 80
      sec 0x5f35c657 nsec 0x26fd29a3 vlan 0 vlan_tpid 0
02:04:12:634473: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:634485: error-drop
  rx:host-eth0
02:04:12:634491: drop
  ethernet-input: l3 mac mismatch

Packet 605

02:04:12:634464: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x26fddde3 vlan 0 vlan_tpid 0
02:04:12:634473: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:634488: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x27b2 dscp CS0 ecn NON_ECN
    fragment id 0xbae6, flags DONT_FRAGMENT
  TCP: 34506 -> 6443
    seq. 0x4301b3fa ack 0x83c29a84
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:634493: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ca 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34506 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:634498: error-drop
  rx:host-eth0
02:04:12:634499: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 606

02:04:12:634464: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 100 snaplen 100 mac 66 net 80
      sec 0x5f35c657 nsec 0x26fe1161 vlan 0 vlan_tpid 0
02:04:12:634473: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:634485: error-drop
  rx:host-eth0
02:04:12:634491: drop
  ethernet-input: l3 mac mismatch

Packet 607

02:04:12:634464: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x26fe6d7d vlan 0 vlan_tpid 0
02:04:12:634473: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:634488: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x27b1 dscp CS0 ecn NON_ECN
    fragment id 0xbae7, flags DONT_FRAGMENT
  TCP: 34506 -> 6443
    seq. 0x4301b3fa ack 0x83c29aa6
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:634493: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ca 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34506 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:634498: error-drop
  rx:host-eth0
02:04:12:634499: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 608

02:04:12:659901: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 274 snaplen 274 mac 66 net 80
      sec 0x5f35c657 nsec 0x286cbcc8 vlan 0 vlan_tpid 0
02:04:12:659912: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:659918: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 260, checksum 0xf9e1 dscp CS0 ecn NON_ECN
    fragment id 0xe7e6, flags DONT_FRAGMENT
  TCP: 34510 -> 6443
    seq. 0x8feff445 ack 0x00e291a6
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:659923: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ce 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34510 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:12:659929: error-drop
  rx:host-eth0
02:04:12:659930: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 609

02:04:12:659901: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x2888e52d vlan 0 vlan_tpid 0
02:04:12:659912: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:659918: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x196b dscp CS0 ecn NON_ECN
    fragment id 0xc92d, flags DONT_FRAGMENT
  TCP: 34502 -> 6443
    seq. 0x07185db4 ack 0x85ba5d9a
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:659923: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86c6 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34502 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:659929: error-drop
  rx:host-eth0
02:04:12:659930: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 610

02:04:12:662022: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c657 nsec 0x28964a50 vlan 0 vlan_tpid 0
02:04:12:662038: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:662048: error-drop
  rx:host-eth0
02:04:12:662055: drop
  ethernet-input: l3 mac mismatch

Packet 611

02:04:12:662022: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x289697ad vlan 0 vlan_tpid 0
02:04:12:662038: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:662050: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xfab0 dscp CS0 ecn NON_ECN
    fragment id 0xe7e7, flags DONT_FRAGMENT
  TCP: 34510 -> 6443
    seq. 0x8feff515 ack 0x00e291be
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:662057: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ce 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34510 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:662064: error-drop
  rx:host-eth0
02:04:12:662064: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 612

02:04:12:662022: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c657 nsec 0x28971dd6 vlan 0 vlan_tpid 0
02:04:12:662038: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:662048: error-drop
  rx:host-eth0
02:04:12:662055: drop
  ethernet-input: l3 mac mismatch

Packet 613

02:04:12:662022: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x28973a76 vlan 0 vlan_tpid 0
02:04:12:662038: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:662050: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xfaaf dscp CS0 ecn NON_ECN
    fragment id 0xe7e8, flags DONT_FRAGMENT
  TCP: 34510 -> 6443
    seq. 0x8feff515 ack 0x00e291d6
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:662057: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ce 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34510 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:662064: error-drop
  rx:host-eth0
02:04:12:662064: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 614

02:04:12:662022: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c657 nsec 0x28978a49 vlan 0 vlan_tpid 0
02:04:12:662038: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:662048: error-drop
  rx:host-eth0
02:04:12:662055: drop
  ethernet-input: l3 mac mismatch

Packet 615

02:04:12:662022: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x2897a21a vlan 0 vlan_tpid 0
02:04:12:662038: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:662050: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xfaae dscp CS0 ecn NON_ECN
    fragment id 0xe7e9, flags DONT_FRAGMENT
  TCP: 34510 -> 6443
    seq. 0x8feff515 ack 0x00e291f0
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:662057: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ce 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34510 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:662064: error-drop
  rx:host-eth0
02:04:12:662064: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 616

02:04:12:662022: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c657 nsec 0x289850e6 vlan 0 vlan_tpid 0
02:04:12:662038: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:662048: error-drop
  rx:host-eth0
02:04:12:662055: drop
  ethernet-input: l3 mac mismatch

Packet 617

02:04:12:662022: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x28986d7c vlan 0 vlan_tpid 0
02:04:12:662038: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:662050: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xfaad dscp CS0 ecn NON_ECN
    fragment id 0xe7ea, flags DONT_FRAGMENT
  TCP: 34510 -> 6443
    seq. 0x8feff515 ack 0x00e2920a
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:662057: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ce 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34510 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:662064: error-drop
  rx:host-eth0
02:04:12:662064: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 618

02:04:12:662022: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 96 snaplen 96 mac 66 net 80
      sec 0x5f35c657 nsec 0x28994527 vlan 0 vlan_tpid 0
02:04:12:662038: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:662048: error-drop
  rx:host-eth0
02:04:12:662055: drop
  ethernet-input: l3 mac mismatch

Packet 619

02:04:12:662022: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x28995fb3 vlan 0 vlan_tpid 0
02:04:12:662038: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:662050: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xfaac dscp CS0 ecn NON_ECN
    fragment id 0xe7eb, flags DONT_FRAGMENT
  TCP: 34510 -> 6443
    seq. 0x8feff515 ack 0x00e29228
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:662057: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ce 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34510 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:662064: error-drop
  rx:host-eth0
02:04:12:662064: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 620

02:04:12:681750: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c657 nsec 0x29d206c9 vlan 0 vlan_tpid 0
02:04:12:681761: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:681767: error-drop
  rx:host-eth0
02:04:12:681773: drop
  ethernet-input: l3 mac mismatch

Packet 621

02:04:12:681750: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x29d30f20 vlan 0 vlan_tpid 0
02:04:12:681761: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:681770: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x27b0 dscp CS0 ecn NON_ECN
    fragment id 0xbae8, flags DONT_FRAGMENT
  TCP: 34506 -> 6443
    seq. 0x4301b3fa ack 0x83c29ac0
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:681775: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ca 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34506 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:681779: error-drop
  rx:host-eth0
02:04:12:681780: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 622

02:04:12:682857: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c657 nsec 0x29db604c vlan 0 vlan_tpid 0
02:04:12:682870: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:682877: error-drop
  rx:host-eth0
02:04:12:682882: drop
  ethernet-input: l3 mac mismatch

Packet 623

02:04:12:682857: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x29dc0395 vlan 0 vlan_tpid 0
02:04:12:682870: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:682879: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x27af dscp CS0 ecn NON_ECN
    fragment id 0xbae9, flags DONT_FRAGMENT
  TCP: 34506 -> 6443
    seq. 0x4301b3fa ack 0x83c29ada
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:682884: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ca 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34506 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:682889: error-drop
  rx:host-eth0
02:04:12:682889: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 624

02:04:12:685557: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c657 nsec 0x29ff5248 vlan 0 vlan_tpid 0
02:04:12:685569: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:685579: error-drop
  rx:host-eth0
02:04:12:685586: drop
  ethernet-input: l3 mac mismatch

Packet 625

02:04:12:685557: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x2a000efd vlan 0 vlan_tpid 0
02:04:12:685569: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:685582: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x27ae dscp CS0 ecn NON_ECN
    fragment id 0xbaea, flags DONT_FRAGMENT
  TCP: 34506 -> 6443
    seq. 0x4301b3fa ack 0x83c29af4
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:685588: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ca 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34506 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:685594: error-drop
  rx:host-eth0
02:04:12:685595: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 626

02:04:12:685557: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 174 snaplen 174 mac 66 net 80
      sec 0x5f35c657 nsec 0x2a04c6a3 vlan 0 vlan_tpid 0
02:04:12:685569: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:685579: error-drop
  rx:host-eth0
02:04:12:685586: drop
  ethernet-input: l3 mac mismatch

Packet 627

02:04:12:685557: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x2a054703 vlan 0 vlan_tpid 0
02:04:12:685569: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:685582: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x27ad dscp CS0 ecn NON_ECN
    fragment id 0xbaeb, flags DONT_FRAGMENT
  TCP: 34506 -> 6443
    seq. 0x4301b3fa ack 0x83c29b60
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:685588: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ca 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34506 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:685594: error-drop
  rx:host-eth0
02:04:12:685595: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 628

02:04:12:685557: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c657 nsec 0x2a07a86c vlan 0 vlan_tpid 0
02:04:12:685569: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:685579: error-drop
  rx:host-eth0
02:04:12:685586: drop
  ethernet-input: l3 mac mismatch

Packet 629

02:04:12:685557: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x2a081528 vlan 0 vlan_tpid 0
02:04:12:685569: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:685582: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x27ac dscp CS0 ecn NON_ECN
    fragment id 0xbaec, flags DONT_FRAGMENT
  TCP: 34506 -> 6443
    seq. 0x4301b3fa ack 0x83c29b78
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:685588: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ca 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34506 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:685594: error-drop
  rx:host-eth0
02:04:12:685595: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 630

02:04:12:685557: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x2a0cefc6 vlan 0 vlan_tpid 0
02:04:12:685569: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:685579: error-drop
  rx:host-eth0
02:04:12:685586: drop
  ethernet-input: l3 mac mismatch

Packet 631

02:04:12:701865: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c657 nsec 0x2b030217 vlan 0 vlan_tpid 0
02:04:12:701877: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:701886: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 76, checksum 0x1952 dscp CS0 ecn NON_ECN
    fragment id 0xc92e, flags DONT_FRAGMENT
  TCP: 34502 -> 6443
    seq. 0x07185db4 ack 0x85ba5d9a
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:701893: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86c6 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34502 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:12:701908: error-drop
  rx:host-eth0
02:04:12:701909: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 632

02:04:12:701865: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000001 len 54 snaplen 54 mac 66 net 80
      sec 0x5f35c657 nsec 0x2b035e09 vlan 0 vlan_tpid 0
02:04:12:701877: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:701891: error-drop
  rx:host-eth0
02:04:12:701906: drop
  ethernet-input: l3 mac mismatch

Packet 633

02:04:12:701865: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 74 snaplen 74 mac 66 net 80
      sec 0x5f35c657 nsec 0x2b05360f vlan 0 vlan_tpid 0
02:04:12:701877: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:701886: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 60, checksum 0xf291 dscp CS0 ecn NON_ECN
    fragment id 0xeffe, flags DONT_FRAGMENT
  TCP: 34544 -> 6443
    seq. 0x97aa238e ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 64240, checksum 0x0000
02:04:12:701893: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f0 0302ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34544 -> 6443 tcp flags (valid) 02 rsvd 0
02:04:12:701908: error-drop
  rx:host-eth0
02:04:12:701909: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 634

02:04:12:701865: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 74 snaplen 74 mac 66 net 80
      sec 0x5f35c657 nsec 0x2b0594a4 vlan 0 vlan_tpid 0
02:04:12:701877: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:701891: error-drop
  rx:host-eth0
02:04:12:701906: drop
  ethernet-input: l3 mac mismatch

Packet 635

02:04:12:701865: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x2b05d2d2 vlan 0 vlan_tpid 0
02:04:12:701877: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:701886: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xf298 dscp CS0 ecn NON_ECN
    fragment id 0xefff, flags DONT_FRAGMENT
  TCP: 34544 -> 6443
    seq. 0x97aa238f ack 0x6549eceb
    flags 0x10 ACK, tcp header: 32 bytes
    window 502, checksum 0x0000
02:04:12:701893: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f0 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34544 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:701908: error-drop
  rx:host-eth0
02:04:12:701909: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 636

02:04:12:710577: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 96 snaplen 96 mac 66 net 80
      sec 0x5f35c657 nsec 0x2b6b25e1 vlan 0 vlan_tpid 0
02:04:12:710588: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:710597: error-drop
  rx:host-eth0
02:04:12:710604: drop
  ethernet-input: l3 mac mismatch

Packet 637

02:04:12:710577: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x2b6c394b vlan 0 vlan_tpid 0
02:04:12:710588: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:710600: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xfaab dscp CS0 ecn NON_ECN
    fragment id 0xe7ec, flags DONT_FRAGMENT
  TCP: 34510 -> 6443
    seq. 0x8feff515 ack 0x00e29246
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:710606: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ce 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34510 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:710611: error-drop
  rx:host-eth0
02:04:12:710611: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 638

02:04:12:713089: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c657 nsec 0x2ba93d33 vlan 0 vlan_tpid 0
02:04:12:713101: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:713115: error-drop
  rx:host-eth0
02:04:12:713122: drop
  ethernet-input: l3 mac mismatch

Packet 639

02:04:12:713089: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x2baa4fa2 vlan 0 vlan_tpid 0
02:04:12:713101: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:713118: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xfaaa dscp CS0 ecn NON_ECN
    fragment id 0xe7ed, flags DONT_FRAGMENT
  TCP: 34510 -> 6443
    seq. 0x8feff515 ack 0x00e29260
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:713124: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ce 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34510 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:713131: error-drop
  rx:host-eth0
02:04:12:713132: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 640

02:04:12:713089: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c657 nsec 0x2babdd7d vlan 0 vlan_tpid 0
02:04:12:713101: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:713115: error-drop
  rx:host-eth0
02:04:12:713122: drop
  ethernet-input: l3 mac mismatch

Packet 641

02:04:12:713089: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x2bac7007 vlan 0 vlan_tpid 0
02:04:12:713101: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:713118: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xfaa9 dscp CS0 ecn NON_ECN
    fragment id 0xe7ee, flags DONT_FRAGMENT
  TCP: 34510 -> 6443
    seq. 0x8feff515 ack 0x00e2927a
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:713124: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ce 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34510 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:713131: error-drop
  rx:host-eth0
02:04:12:713132: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 642

02:04:12:713089: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 122 snaplen 122 mac 66 net 80
      sec 0x5f35c657 nsec 0x2bb1a790 vlan 0 vlan_tpid 0
02:04:12:713101: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:713115: error-drop
  rx:host-eth0
02:04:12:713122: drop
  ethernet-input: l3 mac mismatch

Packet 643

02:04:12:713089: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x2bb21f17 vlan 0 vlan_tpid 0
02:04:12:713101: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:713118: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xfaa8 dscp CS0 ecn NON_ECN
    fragment id 0xe7ef, flags DONT_FRAGMENT
  TCP: 34510 -> 6443
    seq. 0x8feff515 ack 0x00e292b2
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:713124: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ce 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34510 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:713131: error-drop
  rx:host-eth0
02:04:12:713132: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 644

02:04:12:713089: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c657 nsec 0x2bb3f0e0 vlan 0 vlan_tpid 0
02:04:12:713101: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:713115: error-drop
  rx:host-eth0
02:04:12:713122: drop
  ethernet-input: l3 mac mismatch

Packet 645

02:04:12:713089: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x2bb455b0 vlan 0 vlan_tpid 0
02:04:12:713101: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:713118: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xfaa7 dscp CS0 ecn NON_ECN
    fragment id 0xe7f0, flags DONT_FRAGMENT
  TCP: 34510 -> 6443
    seq. 0x8feff515 ack 0x00e292ca
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:713124: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ce 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34510 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:713131: error-drop
  rx:host-eth0
02:04:12:713132: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 646

02:04:12:714208: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c657 nsec 0x2bb77069 vlan 0 vlan_tpid 0
02:04:12:714225: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:714237: error-drop
  rx:host-eth0
02:04:12:714247: drop
  ethernet-input: l3 mac mismatch

Packet 647

02:04:12:714208: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x2bb7d2a3 vlan 0 vlan_tpid 0
02:04:12:714225: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:714240: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xfaa6 dscp CS0 ecn NON_ECN
    fragment id 0xe7f1, flags DONT_FRAGMENT
  TCP: 34510 -> 6443
    seq. 0x8feff515 ack 0x00e292e2
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:714250: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ce 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34510 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:714257: error-drop
  rx:host-eth0
02:04:12:714258: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 648

02:04:12:714208: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c657 nsec 0x2bb7d6e2 vlan 0 vlan_tpid 0
02:04:12:714225: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:714237: error-drop
  rx:host-eth0
02:04:12:714247: drop
  ethernet-input: l3 mac mismatch

Packet 649

02:04:12:714208: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x2bb83dcc vlan 0 vlan_tpid 0
02:04:12:714225: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:714240: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xfaa5 dscp CS0 ecn NON_ECN
    fragment id 0xe7f2, flags DONT_FRAGMENT
  TCP: 34510 -> 6443
    seq. 0x8feff515 ack 0x00e292fc
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:714250: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ce 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34510 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:714257: error-drop
  rx:host-eth0
02:04:12:714258: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 650

02:04:12:714208: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c657 nsec 0x2bb9d3b9 vlan 0 vlan_tpid 0
02:04:12:714225: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:714237: error-drop
  rx:host-eth0
02:04:12:714247: drop
  ethernet-input: l3 mac mismatch

Packet 651

02:04:12:714208: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x2bba42bb vlan 0 vlan_tpid 0
02:04:12:714225: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:714240: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xfaa4 dscp CS0 ecn NON_ECN
    fragment id 0xe7f3, flags DONT_FRAGMENT
  TCP: 34510 -> 6443
    seq. 0x8feff515 ack 0x00e29316
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:714250: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ce 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34510 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:714257: error-drop
  rx:host-eth0
02:04:12:714258: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 652

02:04:12:714208: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c657 nsec 0x2bba6881 vlan 0 vlan_tpid 0
02:04:12:714225: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:714237: error-drop
  rx:host-eth0
02:04:12:714247: drop
  ethernet-input: l3 mac mismatch

Packet 653

02:04:12:714208: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x2bba96fc vlan 0 vlan_tpid 0
02:04:12:714225: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:714240: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xfaa3 dscp CS0 ecn NON_ECN
    fragment id 0xe7f4, flags DONT_FRAGMENT
  TCP: 34510 -> 6443
    seq. 0x8feff515 ack 0x00e29330
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:714250: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ce 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34510 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:714257: error-drop
  rx:host-eth0
02:04:12:714258: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 654

02:04:12:714208: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c657 nsec 0x2bbb4624 vlan 0 vlan_tpid 0
02:04:12:714225: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:714237: error-drop
  rx:host-eth0
02:04:12:714247: drop
  ethernet-input: l3 mac mismatch

Packet 655

02:04:12:714208: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x2bbbc007 vlan 0 vlan_tpid 0
02:04:12:714225: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:714240: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xfaa2 dscp CS0 ecn NON_ECN
    fragment id 0xe7f5, flags DONT_FRAGMENT
  TCP: 34510 -> 6443
    seq. 0x8feff515 ack 0x00e29348
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:714250: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ce 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34510 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:714257: error-drop
  rx:host-eth0
02:04:12:714258: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 656

02:04:12:714208: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c657 nsec 0x2bbd46d5 vlan 0 vlan_tpid 0
02:04:12:714225: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:714237: error-drop
  rx:host-eth0
02:04:12:714247: drop
  ethernet-input: l3 mac mismatch

Packet 657

02:04:12:714208: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x2bbda34b vlan 0 vlan_tpid 0
02:04:12:714225: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:714240: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xfaa1 dscp CS0 ecn NON_ECN
    fragment id 0xe7f6, flags DONT_FRAGMENT
  TCP: 34510 -> 6443
    seq. 0x8feff515 ack 0x00e29360
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:714250: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ce 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34510 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:714257: error-drop
  rx:host-eth0
02:04:12:714258: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 658

02:04:12:714208: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c657 nsec 0x2bbf1820 vlan 0 vlan_tpid 0
02:04:12:714225: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:714237: error-drop
  rx:host-eth0
02:04:12:714247: drop
  ethernet-input: l3 mac mismatch

Packet 659

02:04:12:714208: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x2bbf9410 vlan 0 vlan_tpid 0
02:04:12:714225: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:714240: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xfaa0 dscp CS0 ecn NON_ECN
    fragment id 0xe7f7, flags DONT_FRAGMENT
  TCP: 34510 -> 6443
    seq. 0x8feff515 ack 0x00e2937a
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:714250: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ce 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34510 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:714257: error-drop
  rx:host-eth0
02:04:12:714258: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 660

02:04:12:714208: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c657 nsec 0x2bc11b46 vlan 0 vlan_tpid 0
02:04:12:714225: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:714237: error-drop
  rx:host-eth0
02:04:12:714247: drop
  ethernet-input: l3 mac mismatch

Packet 661

02:04:12:714208: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x2bc179f5 vlan 0 vlan_tpid 0
02:04:12:714225: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:714240: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xfa9f dscp CS0 ecn NON_ECN
    fragment id 0xe7f8, flags DONT_FRAGMENT
  TCP: 34510 -> 6443
    seq. 0x8feff515 ack 0x00e29394
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:714250: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ce 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34510 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:714257: error-drop
  rx:host-eth0
02:04:12:714258: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 662

02:04:12:714208: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c657 nsec 0x2bc29387 vlan 0 vlan_tpid 0
02:04:12:714225: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:714237: error-drop
  rx:host-eth0
02:04:12:714247: drop
  ethernet-input: l3 mac mismatch

Packet 663

02:04:12:714208: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x2bc2e430 vlan 0 vlan_tpid 0
02:04:12:714225: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:714240: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xfa9e dscp CS0 ecn NON_ECN
    fragment id 0xe7f9, flags DONT_FRAGMENT
  TCP: 34510 -> 6443
    seq. 0x8feff515 ack 0x00e293ae
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:714250: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ce 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34510 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:714257: error-drop
  rx:host-eth0
02:04:12:714258: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 664

02:04:12:716454: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c657 nsec 0x2bcf2535 vlan 0 vlan_tpid 0
02:04:12:716469: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:716479: error-drop
  rx:host-eth0
02:04:12:716487: drop
  ethernet-input: l3 mac mismatch

Packet 665

02:04:12:716454: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x2bd01adc vlan 0 vlan_tpid 0
02:04:12:716469: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:716482: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xfa9d dscp CS0 ecn NON_ECN
    fragment id 0xe7fa, flags DONT_FRAGMENT
  TCP: 34510 -> 6443
    seq. 0x8feff515 ack 0x00e293c6
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:716490: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ce 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34510 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:716496: error-drop
  rx:host-eth0
02:04:12:716497: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 666

02:04:12:716454: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c657 nsec 0x2bd0eec7 vlan 0 vlan_tpid 0
02:04:12:716469: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:716479: error-drop
  rx:host-eth0
02:04:12:716487: drop
  ethernet-input: l3 mac mismatch

Packet 667

02:04:12:716454: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x2bd1f99c vlan 0 vlan_tpid 0
02:04:12:716469: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:716482: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xfa9c dscp CS0 ecn NON_ECN
    fragment id 0xe7fb, flags DONT_FRAGMENT
  TCP: 34510 -> 6443
    seq. 0x8feff515 ack 0x00e293de
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:716490: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ce 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34510 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:716496: error-drop
  rx:host-eth0
02:04:12:716497: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 668

02:04:12:716454: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c657 nsec 0x2bd32356 vlan 0 vlan_tpid 0
02:04:12:716469: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:716479: error-drop
  rx:host-eth0
02:04:12:716487: drop
  ethernet-input: l3 mac mismatch

Packet 669

02:04:12:716454: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x2bd39493 vlan 0 vlan_tpid 0
02:04:12:716469: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:716482: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xfa9b dscp CS0 ecn NON_ECN
    fragment id 0xe7fc, flags DONT_FRAGMENT
  TCP: 34510 -> 6443
    seq. 0x8feff515 ack 0x00e293f8
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:716490: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ce 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34510 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:716496: error-drop
  rx:host-eth0
02:04:12:716497: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 670

02:04:12:716454: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c657 nsec 0x2bd4bb5b vlan 0 vlan_tpid 0
02:04:12:716469: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:716479: error-drop
  rx:host-eth0
02:04:12:716487: drop
  ethernet-input: l3 mac mismatch

Packet 671

02:04:12:716454: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x2bd51498 vlan 0 vlan_tpid 0
02:04:12:716469: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:716482: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xfa9a dscp CS0 ecn NON_ECN
    fragment id 0xe7fd, flags DONT_FRAGMENT
  TCP: 34510 -> 6443
    seq. 0x8feff515 ack 0x00e29412
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:716490: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ce 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34510 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:716496: error-drop
  rx:host-eth0
02:04:12:716497: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 672

02:04:12:716454: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c657 nsec 0x2bd62bf1 vlan 0 vlan_tpid 0
02:04:12:716469: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:716479: error-drop
  rx:host-eth0
02:04:12:716487: drop
  ethernet-input: l3 mac mismatch

Packet 673

02:04:12:716454: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x2bd68714 vlan 0 vlan_tpid 0
02:04:12:716469: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:716482: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xfa99 dscp CS0 ecn NON_ECN
    fragment id 0xe7fe, flags DONT_FRAGMENT
  TCP: 34510 -> 6443
    seq. 0x8feff515 ack 0x00e2942c
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:716490: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ce 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34510 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:716496: error-drop
  rx:host-eth0
02:04:12:716497: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 674

02:04:12:716454: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c657 nsec 0x2be3a172 vlan 0 vlan_tpid 0
02:04:12:716469: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:716479: error-drop
  rx:host-eth0
02:04:12:716487: drop
  ethernet-input: l3 mac mismatch

Packet 675

02:04:12:716454: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x2be44d0f vlan 0 vlan_tpid 0
02:04:12:716469: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:716482: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xfa98 dscp CS0 ecn NON_ECN
    fragment id 0xe7ff, flags DONT_FRAGMENT
  TCP: 34510 -> 6443
    seq. 0x8feff515 ack 0x00e29444
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:716490: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ce 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34510 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:716496: error-drop
  rx:host-eth0
02:04:12:716497: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 676

02:04:12:716454: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x2be5c4a4 vlan 0 vlan_tpid 0
02:04:12:716469: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:716479: error-drop
  rx:host-eth0
02:04:12:716487: drop
  ethernet-input: l3 mac mismatch

Packet 677

02:04:12:729035: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x2c969d85 vlan 0 vlan_tpid 0
02:04:12:729043: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:729050: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x27ab dscp CS0 ecn NON_ECN
    fragment id 0xbaed, flags DONT_FRAGMENT
  TCP: 34506 -> 6443
    seq. 0x4301b3fa ack 0x83c29b79
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:729053: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ca 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34506 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:729060: error-drop
  rx:host-eth0
02:04:12:729061: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 678

02:04:12:760428: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x2e7edf93 vlan 0 vlan_tpid 0
02:04:12:760436: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:760441: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xfa97 dscp CS0 ecn NON_ECN
    fragment id 0xe800, flags DONT_FRAGMENT
  TCP: 34510 -> 6443
    seq. 0x8feff515 ack 0x00e29445
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:760445: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ce 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34510 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:760451: error-drop
  rx:host-eth0
02:04:12:760452: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 679

02:04:12:782352: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 74 snaplen 74 mac 66 net 80
      sec 0x5f35c657 nsec 0x2f32fa50 vlan 0 vlan_tpid 0
02:04:12:782365: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:782378: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 60, checksum 0x730f dscp CS0 ecn NON_ECN
    fragment id 0x6f81, flags DONT_FRAGMENT
  TCP: 34552 -> 6443
    seq. 0x72a7a6a3 ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 64240, checksum 0x0000
02:04:12:782382: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f8 0302ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34552 -> 6443 tcp flags (valid) 02 rsvd 0
02:04:12:782387: error-drop
  rx:host-eth0
02:04:12:782388: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 680

02:04:12:782352: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 74 snaplen 74 mac 66 net 80
      sec 0x5f35c657 nsec 0x2f338495 vlan 0 vlan_tpid 0
02:04:12:782365: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:782376: error-drop
  rx:host-eth0
02:04:12:782381: drop
  ethernet-input: l3 mac mismatch

Packet 681

02:04:12:782352: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x2f33c985 vlan 0 vlan_tpid 0
02:04:12:782365: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:782378: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x7316 dscp CS0 ecn NON_ECN
    fragment id 0x6f82, flags DONT_FRAGMENT
  TCP: 34552 -> 6443
    seq. 0x72a7a6a4 ack 0x6ce46279
    flags 0x10 ACK, tcp header: 32 bytes
    window 502, checksum 0x0000
02:04:12:782382: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f8 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34552 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:782387: error-drop
  rx:host-eth0
02:04:12:782388: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 682

02:04:12:782352: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 192 snaplen 192 mac 66 net 80
      sec 0x5f35c657 nsec 0x2f363835 vlan 0 vlan_tpid 0
02:04:12:782365: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:782378: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 178, checksum 0x272c dscp CS0 ecn NON_ECN
    fragment id 0xbaee, flags DONT_FRAGMENT
  TCP: 34506 -> 6443
    seq. 0x4301b3fa ack 0x83c29b79
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:782382: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ca 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34506 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:12:782387: error-drop
  rx:host-eth0
02:04:12:782388: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 683

02:04:12:782352: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000001 len 54 snaplen 54 mac 66 net 80
      sec 0x5f35c657 nsec 0x2f3668c2 vlan 0 vlan_tpid 0
02:04:12:782365: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:782376: error-drop
  rx:host-eth0
02:04:12:782381: drop
  ethernet-input: l3 mac mismatch

Packet 684

02:04:12:782352: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 305 snaplen 305 mac 66 net 80
      sec 0x5f35c657 nsec 0x2f471a6f vlan 0 vlan_tpid 0
02:04:12:782365: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:782378: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 291, checksum 0xf1a8 dscp CS0 ecn NON_ECN
    fragment id 0xf000, flags DONT_FRAGMENT
  TCP: 34544 -> 6443
    seq. 0x97aa238f ack 0x6549eceb
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 502, checksum 0x0000
02:04:12:782382: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f0 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34544 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:12:782387: error-drop
  rx:host-eth0
02:04:12:782388: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 685

02:04:12:782352: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x2f47624a vlan 0 vlan_tpid 0
02:04:12:782365: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:782376: error-drop
  rx:host-eth0
02:04:12:782381: drop
  ethernet-input: l3 mac mismatch

Packet 686

02:04:12:782352: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 1647 snaplen 1647 mac 66 net 80
      sec 0x5f35c657 nsec 0x2faa3ad2 vlan 0 vlan_tpid 0
02:04:12:782365: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:782376: error-drop
  rx:host-eth0
02:04:12:782381: drop
  ethernet-input: l3 mac mismatch

Packet 687

02:04:12:782352: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x2faaba3e vlan 0 vlan_tpid 0
02:04:12:782365: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:782378: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xf296 dscp CS0 ecn NON_ECN
    fragment id 0xf001, flags DONT_FRAGMENT
  TCP: 34544 -> 6443
    seq. 0x97aa247e ack 0x6549f318
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:782382: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f0 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34544 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:782387: error-drop
  rx:host-eth0
02:04:12:782388: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 688

02:04:12:795773: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 74 snaplen 74 mac 66 net 80
      sec 0x5f35c657 nsec 0x308d2abf vlan 0 vlan_tpid 0
02:04:12:795785: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:795794: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 60, checksum 0x2944 dscp CS0 ecn NON_ECN
    fragment id 0xb94c, flags DONT_FRAGMENT
  TCP: 34556 -> 6443
    seq. 0x67b1d02e ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 64240, checksum 0x0000
02:04:12:795800: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86fc 0302ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34556 -> 6443 tcp flags (valid) 02 rsvd 0
02:04:12:795805: error-drop
  rx:host-eth0
02:04:12:795806: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 689

02:04:12:795773: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 74 snaplen 74 mac 66 net 80
      sec 0x5f35c657 nsec 0x308db24c vlan 0 vlan_tpid 0
02:04:12:795785: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:795792: error-drop
  rx:host-eth0
02:04:12:795798: drop
  ethernet-input: l3 mac mismatch

Packet 690

02:04:12:795773: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x308df8ce vlan 0 vlan_tpid 0
02:04:12:795785: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:795794: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x294b dscp CS0 ecn NON_ECN
    fragment id 0xb94d, flags DONT_FRAGMENT
  TCP: 34556 -> 6443
    seq. 0x67b1d02f ack 0xdf4a4c09
    flags 0x10 ACK, tcp header: 32 bytes
    window 502, checksum 0x0000
02:04:12:795800: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86fc 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34556 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:795805: error-drop
  rx:host-eth0
02:04:12:795806: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 691

02:04:12:795773: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c657 nsec 0x308ed0dd vlan 0 vlan_tpid 0
02:04:12:795785: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:795794: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 76, checksum 0xfa7e dscp CS0 ecn NON_ECN
    fragment id 0xe801, flags DONT_FRAGMENT
  TCP: 34510 -> 6443
    seq. 0x8feff515 ack 0x00e29445
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:795800: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86ce 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34510 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:12:795805: error-drop
  rx:host-eth0
02:04:12:795806: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 692

02:04:12:795773: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000001 len 54 snaplen 54 mac 66 net 80
      sec 0x5f35c657 nsec 0x308f1107 vlan 0 vlan_tpid 0
02:04:12:795785: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:795792: error-drop
  rx:host-eth0
02:04:12:795798: drop
  ethernet-input: l3 mac mismatch

Packet 693

02:04:12:831508: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 305 snaplen 305 mac 66 net 80
      sec 0x5f35c657 nsec 0x32927fc8 vlan 0 vlan_tpid 0
02:04:12:831519: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:831526: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 291, checksum 0x7226 dscp CS0 ecn NON_ECN
    fragment id 0x6f83, flags DONT_FRAGMENT
  TCP: 34552 -> 6443
    seq. 0x72a7a6a4 ack 0x6ce46279
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 502, checksum 0x0000
02:04:12:831531: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f8 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34552 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:12:831540: error-drop
  rx:host-eth0
02:04:12:831540: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 694

02:04:12:831508: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x3292d80b vlan 0 vlan_tpid 0
02:04:12:831519: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:831530: error-drop
  rx:host-eth0
02:04:12:831536: drop
  ethernet-input: l3 mac mismatch

Packet 695

02:04:12:831508: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 1647 snaplen 1647 mac 66 net 80
      sec 0x5f35c657 nsec 0x32c22102 vlan 0 vlan_tpid 0
02:04:12:831519: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:831530: error-drop
  rx:host-eth0
02:04:12:831536: drop
  ethernet-input: l3 mac mismatch

Packet 696

02:04:12:831508: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x32c283cd vlan 0 vlan_tpid 0
02:04:12:831519: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:831526: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x7314 dscp CS0 ecn NON_ECN
    fragment id 0x6f84, flags DONT_FRAGMENT
  TCP: 34552 -> 6443
    seq. 0x72a7a793 ack 0x6ce468a6
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:831531: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f8 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34552 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:831540: error-drop
  rx:host-eth0
02:04:12:831540: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 697

02:04:12:843719: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 1717 snaplen 1717 mac 66 net 80
      sec 0x5f35c657 nsec 0x336d92f8 vlan 0 vlan_tpid 0
02:04:12:843727: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:843734: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 1703, checksum 0xec22 dscp CS0 ecn NON_ECN
    fragment id 0xf002, flags DONT_FRAGMENT
  TCP: 34544 -> 6443
    seq. 0x97aa247e ack 0x6549f318
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:843739: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f0 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34544 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:12:843747: error-drop
  rx:host-eth0
02:04:12:843747: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 698

02:04:12:843719: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x336ded75 vlan 0 vlan_tpid 0
02:04:12:843727: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:843737: error-drop
  rx:host-eth0
02:04:12:843745: drop
  ethernet-input: l3 mac mismatch

Packet 699

02:04:12:851158: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 305 snaplen 305 mac 66 net 80
      sec 0x5f35c657 nsec 0x33b90426 vlan 0 vlan_tpid 0
02:04:12:851168: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:851176: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 291, checksum 0x285b dscp CS0 ecn NON_ECN
    fragment id 0xb94e, flags DONT_FRAGMENT
  TCP: 34556 -> 6443
    seq. 0x67b1d02f ack 0xdf4a4c09
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 502, checksum 0x0000
02:04:12:851182: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86fc 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34556 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:12:851190: error-drop
  rx:host-eth0
02:04:12:851190: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 700

02:04:12:851158: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x33b953f3 vlan 0 vlan_tpid 0
02:04:12:851168: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:851181: error-drop
  rx:host-eth0
02:04:12:851187: drop
  ethernet-input: l3 mac mismatch

Packet 701

02:04:12:851158: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 1647 snaplen 1647 mac 66 net 80
      sec 0x5f35c657 nsec 0x33e7f8b6 vlan 0 vlan_tpid 0
02:04:12:851168: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:851181: error-drop
  rx:host-eth0
02:04:12:851187: drop
  ethernet-input: l3 mac mismatch

Packet 702

02:04:12:851158: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x33e85a11 vlan 0 vlan_tpid 0
02:04:12:851168: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:851176: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x2949 dscp CS0 ecn NON_ECN
    fragment id 0xb94f, flags DONT_FRAGMENT
  TCP: 34556 -> 6443
    seq. 0x67b1d11e ack 0xdf4a5236
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:851182: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86fc 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34556 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:851190: error-drop
  rx:host-eth0
02:04:12:851190: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 703

02:04:12:861838: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 247 snaplen 247 mac 66 net 80
      sec 0x5f35c657 nsec 0x348faab5 vlan 0 vlan_tpid 0
02:04:12:861849: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:861856: error-drop
  rx:host-eth0
02:04:12:861861: drop
  ethernet-input: l3 mac mismatch

Packet 704

02:04:12:861838: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x34900f88 vlan 0 vlan_tpid 0
02:04:12:861849: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:861859: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xf293 dscp CS0 ecn NON_ECN
    fragment id 0xf004, flags DONT_FRAGMENT
  TCP: 34544 -> 6443
    seq. 0x97aa2af1 ack 0x6549f3cd
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:861864: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f0 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34544 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:861869: error-drop
  rx:host-eth0
02:04:12:861870: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 705

02:04:12:897084: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 1712 snaplen 1712 mac 66 net 80
      sec 0x5f35c657 nsec 0x36882d19 vlan 0 vlan_tpid 0
02:04:12:897093: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:897099: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 1698, checksum 0x6ca5 dscp CS0 ecn NON_ECN
    fragment id 0x6f85, flags DONT_FRAGMENT
  TCP: 34552 -> 6443
    seq. 0x72a7a793 ack 0x6ce468a6
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:897104: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f8 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34552 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:12:897110: error-drop
  rx:host-eth0
02:04:12:897110: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 706

02:04:12:897084: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x36889023 vlan 0 vlan_tpid 0
02:04:12:897093: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:897103: error-drop
  rx:host-eth0
02:04:12:897108: drop
  ethernet-input: l3 mac mismatch

Packet 707

02:04:12:922087: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 1717 snaplen 1717 mac 66 net 80
      sec 0x5f35c657 nsec 0x3822022c vlan 0 vlan_tpid 0
02:04:12:922097: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:922104: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 1703, checksum 0x22d5 dscp CS0 ecn NON_ECN
    fragment id 0xb950, flags DONT_FRAGMENT
  TCP: 34556 -> 6443
    seq. 0x67b1d11e ack 0xdf4a5236
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:922109: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86fc 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34556 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:12:922115: error-drop
  rx:host-eth0
02:04:12:922116: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 708

02:04:12:922087: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x38227923 vlan 0 vlan_tpid 0
02:04:12:922097: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:922108: error-drop
  rx:host-eth0
02:04:12:922113: drop
  ethernet-input: l3 mac mismatch

Packet 709

02:04:12:934445: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 291 snaplen 291 mac 66 net 80
      sec 0x5f35c657 nsec 0x38936cb9 vlan 0 vlan_tpid 0
02:04:12:934457: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:934465: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 277, checksum 0xf1b1 dscp CS0 ecn NON_ECN
    fragment id 0xf005, flags DONT_FRAGMENT
  TCP: 34544 -> 6443
    seq. 0x97aa2af1 ack 0x6549f3cd
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:934470: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f0 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34544 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:12:934479: error-drop
  rx:host-eth0
02:04:12:934479: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 710

02:04:12:934445: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x3893b308 vlan 0 vlan_tpid 0
02:04:12:934457: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:934469: error-drop
  rx:host-eth0
02:04:12:934476: drop
  ethernet-input: l3 mac mismatch

Packet 711

02:04:12:953656: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 116 snaplen 116 mac 66 net 80
      sec 0x5f35c657 nsec 0x39fa7da6 vlan 0 vlan_tpid 0
02:04:12:953663: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:953670: error-drop
  rx:host-eth0
02:04:12:953676: drop
  ethernet-input: l3 mac mismatch

Packet 712

02:04:12:953656: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x39fad180 vlan 0 vlan_tpid 0
02:04:12:953663: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:953673: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xf291 dscp CS0 ecn NON_ECN
    fragment id 0xf006, flags DONT_FRAGMENT
  TCP: 34544 -> 6443
    seq. 0x97aa2bd2 ack 0x6549f3ff
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:953678: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f0 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34544 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:953684: error-drop
  rx:host-eth0
02:04:12:953684: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 713

02:04:12:956907: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 247 snaplen 247 mac 66 net 80
      sec 0x5f35c657 nsec 0x3a2b34ef vlan 0 vlan_tpid 0
02:04:12:956916: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:956922: error-drop
  rx:host-eth0
02:04:12:956927: drop
  ethernet-input: l3 mac mismatch

Packet 714

02:04:12:956907: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x3a2baf75 vlan 0 vlan_tpid 0
02:04:12:956916: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:956924: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x2946 dscp CS0 ecn NON_ECN
    fragment id 0xb952, flags DONT_FRAGMENT
  TCP: 34556 -> 6443
    seq. 0x67b1d791 ack 0xdf4a52eb
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:956929: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86fc 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34556 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:956933: error-drop
  rx:host-eth0
02:04:12:956933: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 715

02:04:12:966642: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 247 snaplen 247 mac 66 net 80
      sec 0x5f35c657 nsec 0x3ab89c87 vlan 0 vlan_tpid 0
02:04:12:966651: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:12:966659: error-drop
  rx:host-eth0
02:04:12:966665: drop
  ethernet-input: l3 mac mismatch

Packet 716

02:04:12:966642: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c657 nsec 0x3ab90a7a vlan 0 vlan_tpid 0
02:04:12:966651: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:12:966662: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x7311 dscp CS0 ecn NON_ECN
    fragment id 0x6f87, flags DONT_FRAGMENT
  TCP: 34552 -> 6443
    seq. 0x72a7ae01 ack 0x6ce4695b
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:12:966667: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f8 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34552 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:12:966673: error-drop
  rx:host-eth0
02:04:12:966674: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 717

02:04:13:011211: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 275 snaplen 275 mac 66 net 80
      sec 0x5f35c658 nsec 0x1ce17dc vlan 0 vlan_tpid 0
02:04:13:011222: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:011229: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 261, checksum 0xf1bf dscp CS0 ecn NON_ECN
    fragment id 0xf007, flags DONT_FRAGMENT
  TCP: 34544 -> 6443
    seq. 0x97aa2bd2 ack 0x6549f3ff
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:011237: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f0 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34544 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:13:011246: error-drop
  rx:host-eth0
02:04:13:011246: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 718

02:04:13:011211: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 108 snaplen 108 mac 66 net 80
      sec 0x5f35c658 nsec 0x1db7416 vlan 0 vlan_tpid 0
02:04:13:011222: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:011235: error-drop
  rx:host-eth0
02:04:13:011243: drop
  ethernet-input: l3 mac mismatch

Packet 719

02:04:13:011211: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x1dbca0f vlan 0 vlan_tpid 0
02:04:13:011222: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:011229: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xf28f dscp CS0 ecn NON_ECN
    fragment id 0xf008, flags DONT_FRAGMENT
  TCP: 34544 -> 6443
    seq. 0x97aa2ca3 ack 0x6549f429
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:011237: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f0 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34544 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:011246: error-drop
  rx:host-eth0
02:04:13:011246: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 720

02:04:13:018815: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 291 snaplen 291 mac 66 net 80
      sec 0x5f35c658 nsec 0x24ee219 vlan 0 vlan_tpid 0
02:04:13:018825: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:018831: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 277, checksum 0x2864 dscp CS0 ecn NON_ECN
    fragment id 0xb953, flags DONT_FRAGMENT
  TCP: 34556 -> 6443
    seq. 0x67b1d791 ack 0xdf4a52eb
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:018838: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86fc 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34556 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:13:018845: error-drop
  rx:host-eth0
02:04:13:018846: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 721

02:04:13:018815: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x24f2437 vlan 0 vlan_tpid 0
02:04:13:018825: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:018836: error-drop
  rx:host-eth0
02:04:13:018843: drop
  ethernet-input: l3 mac mismatch

Packet 722

02:04:13:019917: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c658 nsec 0x25cf3b1 vlan 0 vlan_tpid 0
02:04:13:019926: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:019939: error-drop
  rx:host-eth0
02:04:13:019946: drop
  ethernet-input: l3 mac mismatch

Packet 723

02:04:13:019917: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x25d4954 vlan 0 vlan_tpid 0
02:04:13:019926: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:019934: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x2944 dscp CS0 ecn NON_ECN
    fragment id 0xb954, flags DONT_FRAGMENT
  TCP: 34556 -> 6443
    seq. 0x67b1d872 ack 0xdf4a5305
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:019941: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86fc 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34556 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:019948: error-drop
  rx:host-eth0
02:04:13:019948: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 724

02:04:13:019917: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 112 snaplen 112 mac 66 net 80
      sec 0x5f35c658 nsec 0x25dadb6 vlan 0 vlan_tpid 0
02:04:13:019926: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:019939: error-drop
  rx:host-eth0
02:04:13:019946: drop
  ethernet-input: l3 mac mismatch

Packet 725

02:04:13:019917: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x25dca86 vlan 0 vlan_tpid 0
02:04:13:019926: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:019934: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x2943 dscp CS0 ecn NON_ECN
    fragment id 0xb955, flags DONT_FRAGMENT
  TCP: 34556 -> 6443
    seq. 0x67b1d872 ack 0xdf4a5333
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:019941: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86fc 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34556 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:019948: error-drop
  rx:host-eth0
02:04:13:019948: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 726

02:04:13:025071: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 291 snaplen 291 mac 66 net 80
      sec 0x5f35c658 nsec 0x29cf8d2 vlan 0 vlan_tpid 0
02:04:13:025081: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:025089: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 277, checksum 0x722f dscp CS0 ecn NON_ECN
    fragment id 0x6f88, flags DONT_FRAGMENT
  TCP: 34552 -> 6443
    seq. 0x72a7ae01 ack 0x6ce4695b
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:025095: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f8 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34552 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:13:025104: error-drop
  rx:host-eth0
02:04:13:025105: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 727

02:04:13:025071: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x29d355d vlan 0 vlan_tpid 0
02:04:13:025081: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:025094: error-drop
  rx:host-eth0
02:04:13:025102: drop
  ethernet-input: l3 mac mismatch

Packet 728

02:04:13:026183: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c658 nsec 0x2b3365f vlan 0 vlan_tpid 0
02:04:13:026202: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:026220: error-drop
  rx:host-eth0
02:04:13:026227: drop
  ethernet-input: l3 mac mismatch

Packet 729

02:04:13:026183: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x2b384f9 vlan 0 vlan_tpid 0
02:04:13:026202: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:026209: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x730f dscp CS0 ecn NON_ECN
    fragment id 0x6f89, flags DONT_FRAGMENT
  TCP: 34552 -> 6443
    seq. 0x72a7aee2 ack 0x6ce46975
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:026222: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f8 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34552 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:026229: error-drop
  rx:host-eth0
02:04:13:026229: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 730

02:04:13:026183: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 112 snaplen 112 mac 66 net 80
      sec 0x5f35c658 nsec 0x2b3d97f vlan 0 vlan_tpid 0
02:04:13:026202: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:026220: error-drop
  rx:host-eth0
02:04:13:026227: drop
  ethernet-input: l3 mac mismatch

Packet 731

02:04:13:026183: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x2b40402 vlan 0 vlan_tpid 0
02:04:13:026202: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:026209: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x730e dscp CS0 ecn NON_ECN
    fragment id 0x6f8a, flags DONT_FRAGMENT
  TCP: 34552 -> 6443
    seq. 0x72a7aee2 ack 0x6ce469a3
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:026222: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f8 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34552 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:026229: error-drop
  rx:host-eth0
02:04:13:026229: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 732

02:04:13:079329: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 274 snaplen 274 mac 66 net 80
      sec 0x5f35c658 nsec 0x5d9a4a2 vlan 0 vlan_tpid 0
02:04:13:079339: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:079388: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 260, checksum 0xf1be dscp CS0 ecn NON_ECN
    fragment id 0xf009, flags DONT_FRAGMENT
  TCP: 34544 -> 6443
    seq. 0x97aa2ca3 ack 0x6549f429
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:079394: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f0 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34544 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:13:079400: error-drop
  rx:host-eth0
02:04:13:079401: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 733

02:04:13:079329: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 96 snaplen 96 mac 66 net 80
      sec 0x5f35c658 nsec 0x5e9638d vlan 0 vlan_tpid 0
02:04:13:079339: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:079384: error-drop
  rx:host-eth0
02:04:13:079392: drop
  ethernet-input: l3 mac mismatch

Packet 734

02:04:13:079329: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x5e9a7b6 vlan 0 vlan_tpid 0
02:04:13:079339: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:079388: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xf28d dscp CS0 ecn NON_ECN
    fragment id 0xf00a, flags DONT_FRAGMENT
  TCP: 34544 -> 6443
    seq. 0x97aa2d73 ack 0x6549f447
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:079394: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f0 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34544 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:079400: error-drop
  rx:host-eth0
02:04:13:079401: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 735

02:04:13:079329: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 100 snaplen 100 mac 66 net 80
      sec 0x5f35c658 nsec 0x5ea34cc vlan 0 vlan_tpid 0
02:04:13:079339: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:079384: error-drop
  rx:host-eth0
02:04:13:079392: drop
  ethernet-input: l3 mac mismatch

Packet 736

02:04:13:079329: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x5ea55fc vlan 0 vlan_tpid 0
02:04:13:079339: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:079388: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xf28c dscp CS0 ecn NON_ECN
    fragment id 0xf00b, flags DONT_FRAGMENT
  TCP: 34544 -> 6443
    seq. 0x97aa2d73 ack 0x6549f469
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:079394: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f0 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34544 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:079400: error-drop
  rx:host-eth0
02:04:13:079401: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 737

02:04:13:089003: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 275 snaplen 275 mac 66 net 80
      sec 0x5f35c658 nsec 0x67947d9 vlan 0 vlan_tpid 0
02:04:13:089013: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:089019: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 261, checksum 0x723c dscp CS0 ecn NON_ECN
    fragment id 0x6f8b, flags DONT_FRAGMENT
  TCP: 34552 -> 6443
    seq. 0x72a7aee2 ack 0x6ce469a3
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:089025: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f8 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34552 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:13:089033: error-drop
  rx:host-eth0
02:04:13:089033: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 738

02:04:13:089003: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x679872c vlan 0 vlan_tpid 0
02:04:13:089013: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:089024: error-drop
  rx:host-eth0
02:04:13:089031: drop
  ethernet-input: l3 mac mismatch

Packet 739

02:04:13:089003: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 275 snaplen 275 mac 66 net 80
      sec 0x5f35c658 nsec 0x67a5447 vlan 0 vlan_tpid 0
02:04:13:089013: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:089019: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 261, checksum 0x2871 dscp CS0 ecn NON_ECN
    fragment id 0xb956, flags DONT_FRAGMENT
  TCP: 34556 -> 6443
    seq. 0x67b1d872 ack 0xdf4a5333
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:089025: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86fc 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34556 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:13:089033: error-drop
  rx:host-eth0
02:04:13:089033: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 740

02:04:13:090184: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 100 snaplen 100 mac 66 net 80
      sec 0x5f35c658 nsec 0x683abff vlan 0 vlan_tpid 0
02:04:13:090198: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:090210: error-drop
  rx:host-eth0
02:04:13:090220: drop
  ethernet-input: l3 mac mismatch

Packet 741

02:04:13:090184: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x683ea12 vlan 0 vlan_tpid 0
02:04:13:090198: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:090213: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x2941 dscp CS0 ecn NON_ECN
    fragment id 0xb957, flags DONT_FRAGMENT
  TCP: 34556 -> 6443
    seq. 0x67b1d943 ack 0xdf4a5355
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:090223: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86fc 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34556 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:090230: error-drop
  rx:host-eth0
02:04:13:090231: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 742

02:04:13:090184: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 96 snaplen 96 mac 66 net 80
      sec 0x5f35c658 nsec 0x68443eb vlan 0 vlan_tpid 0
02:04:13:090198: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:090210: error-drop
  rx:host-eth0
02:04:13:090220: drop
  ethernet-input: l3 mac mismatch

Packet 743

02:04:13:090184: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x6845d94 vlan 0 vlan_tpid 0
02:04:13:090198: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:090213: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x2940 dscp CS0 ecn NON_ECN
    fragment id 0xb958, flags DONT_FRAGMENT
  TCP: 34556 -> 6443
    seq. 0x67b1d943 ack 0xdf4a5373
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:090223: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86fc 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34556 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:090230: error-drop
  rx:host-eth0
02:04:13:090231: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 744

02:04:13:090184: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c658 nsec 0x68952ed vlan 0 vlan_tpid 0
02:04:13:090198: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:090210: error-drop
  rx:host-eth0
02:04:13:090220: drop
  ethernet-input: l3 mac mismatch

Packet 745

02:04:13:090184: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x68983ea vlan 0 vlan_tpid 0
02:04:13:090198: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:090213: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x730c dscp CS0 ecn NON_ECN
    fragment id 0x6f8c, flags DONT_FRAGMENT
  TCP: 34552 -> 6443
    seq. 0x72a7afb3 ack 0x6ce469bb
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:090223: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f8 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34552 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:090230: error-drop
  rx:host-eth0
02:04:13:090231: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 746

02:04:13:090184: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c658 nsec 0x68afcf7 vlan 0 vlan_tpid 0
02:04:13:090198: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:090210: error-drop
  rx:host-eth0
02:04:13:090220: drop
  ethernet-input: l3 mac mismatch

Packet 747

02:04:13:090184: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x68b1e43 vlan 0 vlan_tpid 0
02:04:13:090198: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:090213: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x730b dscp CS0 ecn NON_ECN
    fragment id 0x6f8d, flags DONT_FRAGMENT
  TCP: 34552 -> 6443
    seq. 0x72a7afb3 ack 0x6ce469d3
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:090223: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f8 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34552 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:090230: error-drop
  rx:host-eth0
02:04:13:090231: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 748

02:04:13:090184: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c658 nsec 0x68c2282 vlan 0 vlan_tpid 0
02:04:13:090198: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:090210: error-drop
  rx:host-eth0
02:04:13:090220: drop
  ethernet-input: l3 mac mismatch

Packet 749

02:04:13:090184: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x68c4143 vlan 0 vlan_tpid 0
02:04:13:090198: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:090213: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x730a dscp CS0 ecn NON_ECN
    fragment id 0x6f8e, flags DONT_FRAGMENT
  TCP: 34552 -> 6443
    seq. 0x72a7afb3 ack 0x6ce469ed
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:090223: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f8 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34552 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:090230: error-drop
  rx:host-eth0
02:04:13:090231: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 750

02:04:13:090184: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c658 nsec 0x68d274c vlan 0 vlan_tpid 0
02:04:13:090198: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:090210: error-drop
  rx:host-eth0
02:04:13:090220: drop
  ethernet-input: l3 mac mismatch

Packet 751

02:04:13:090184: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x68d426e vlan 0 vlan_tpid 0
02:04:13:090198: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:090213: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x7309 dscp CS0 ecn NON_ECN
    fragment id 0x6f8f, flags DONT_FRAGMENT
  TCP: 34552 -> 6443
    seq. 0x72a7afb3 ack 0x6ce46a07
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:090223: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f8 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34552 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:090230: error-drop
  rx:host-eth0
02:04:13:090231: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 752

02:04:13:090184: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 96 snaplen 96 mac 66 net 80
      sec 0x5f35c658 nsec 0x68e1593 vlan 0 vlan_tpid 0
02:04:13:090198: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:090210: error-drop
  rx:host-eth0
02:04:13:090220: drop
  ethernet-input: l3 mac mismatch

Packet 753

02:04:13:090184: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x68e33c1 vlan 0 vlan_tpid 0
02:04:13:090198: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:090213: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x7308 dscp CS0 ecn NON_ECN
    fragment id 0x6f90, flags DONT_FRAGMENT
  TCP: 34552 -> 6443
    seq. 0x72a7afb3 ack 0x6ce46a25
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:090223: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f8 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34552 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:090230: error-drop
  rx:host-eth0
02:04:13:090231: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 754

02:04:13:137404: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 96 snaplen 96 mac 66 net 80
      sec 0x5f35c658 nsec 0x94222c5 vlan 0 vlan_tpid 0
02:04:13:137412: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:137418: error-drop
  rx:host-eth0
02:04:13:137422: drop
  ethernet-input: l3 mac mismatch

Packet 755

02:04:13:137404: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x9428c8c vlan 0 vlan_tpid 0
02:04:13:137412: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:137420: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xf28b dscp CS0 ecn NON_ECN
    fragment id 0xf00c, flags DONT_FRAGMENT
  TCP: 34544 -> 6443
    seq. 0x97aa2d73 ack 0x6549f487
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:137423: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f0 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34544 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:137428: error-drop
  rx:host-eth0
02:04:13:137428: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 756

02:04:13:141744: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 130 snaplen 130 mac 66 net 80
      sec 0x5f35c658 nsec 0x993e6e8 vlan 0 vlan_tpid 0
02:04:13:141761: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:141773: error-drop
  rx:host-eth0
02:04:13:141782: drop
  ethernet-input: l3 mac mismatch

Packet 757

02:04:13:141744: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x9944be1 vlan 0 vlan_tpid 0
02:04:13:141761: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:141777: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xf28a dscp CS0 ecn NON_ECN
    fragment id 0xf00d, flags DONT_FRAGMENT
  TCP: 34544 -> 6443
    seq. 0x97aa2d73 ack 0x6549f4c7
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:141785: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f0 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34544 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:141793: error-drop
  rx:host-eth0
02:04:13:141794: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 758

02:04:13:141744: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 104 snaplen 104 mac 66 net 80
      sec 0x5f35c658 nsec 0x9992d26 vlan 0 vlan_tpid 0
02:04:13:141761: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:141773: error-drop
  rx:host-eth0
02:04:13:141782: drop
  ethernet-input: l3 mac mismatch

Packet 759

02:04:13:141744: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x99959b9 vlan 0 vlan_tpid 0
02:04:13:141761: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:141777: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xf289 dscp CS0 ecn NON_ECN
    fragment id 0xf00e, flags DONT_FRAGMENT
  TCP: 34544 -> 6443
    seq. 0x97aa2d73 ack 0x6549f4ed
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:141785: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f0 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34544 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:141793: error-drop
  rx:host-eth0
02:04:13:141794: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 760

02:04:13:141744: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c658 nsec 0x999a090 vlan 0 vlan_tpid 0
02:04:13:141761: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:141773: error-drop
  rx:host-eth0
02:04:13:141782: drop
  ethernet-input: l3 mac mismatch

Packet 761

02:04:13:141744: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x999b8f3 vlan 0 vlan_tpid 0
02:04:13:141761: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:141777: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xf288 dscp CS0 ecn NON_ECN
    fragment id 0xf00f, flags DONT_FRAGMENT
  TCP: 34544 -> 6443
    seq. 0x97aa2d73 ack 0x6549f505
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:141785: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f0 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34544 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:141793: error-drop
  rx:host-eth0
02:04:13:141794: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 762

02:04:13:141744: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c658 nsec 0x99a0f09 vlan 0 vlan_tpid 0
02:04:13:141761: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:141773: error-drop
  rx:host-eth0
02:04:13:141782: drop
  ethernet-input: l3 mac mismatch

Packet 763

02:04:13:141744: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x99a2823 vlan 0 vlan_tpid 0
02:04:13:141761: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:141777: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xf287 dscp CS0 ecn NON_ECN
    fragment id 0xf010, flags DONT_FRAGMENT
  TCP: 34544 -> 6443
    seq. 0x97aa2d73 ack 0x6549f51d
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:141785: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f0 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34544 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:141793: error-drop
  rx:host-eth0
02:04:13:141794: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 764

02:04:13:141744: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c658 nsec 0x99a55ec vlan 0 vlan_tpid 0
02:04:13:141761: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:141773: error-drop
  rx:host-eth0
02:04:13:141782: drop
  ethernet-input: l3 mac mismatch

Packet 765

02:04:13:141744: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x99aaab9 vlan 0 vlan_tpid 0
02:04:13:141761: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:141777: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xf286 dscp CS0 ecn NON_ECN
    fragment id 0xf011, flags DONT_FRAGMENT
  TCP: 34544 -> 6443
    seq. 0x97aa2d73 ack 0x6549f537
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:141785: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f0 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34544 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:141793: error-drop
  rx:host-eth0
02:04:13:141794: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 766

02:04:13:141744: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 96 snaplen 96 mac 66 net 80
      sec 0x5f35c658 nsec 0x99b6cb8 vlan 0 vlan_tpid 0
02:04:13:141761: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:141773: error-drop
  rx:host-eth0
02:04:13:141782: drop
  ethernet-input: l3 mac mismatch

Packet 767

02:04:13:141744: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x99bb51b vlan 0 vlan_tpid 0
02:04:13:141761: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:141777: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xf285 dscp CS0 ecn NON_ECN
    fragment id 0xf012, flags DONT_FRAGMENT
  TCP: 34544 -> 6443
    seq. 0x97aa2d73 ack 0x6549f555
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:141785: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f0 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34544 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:141793: error-drop
  rx:host-eth0
02:04:13:141794: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 768

02:04:13:141744: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 96 snaplen 96 mac 66 net 80
      sec 0x5f35c658 nsec 0x99d0f07 vlan 0 vlan_tpid 0
02:04:13:141761: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:141773: error-drop
  rx:host-eth0
02:04:13:141782: drop
  ethernet-input: l3 mac mismatch

Packet 769

02:04:13:141744: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x99d7f06 vlan 0 vlan_tpid 0
02:04:13:141761: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:141777: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xf284 dscp CS0 ecn NON_ECN
    fragment id 0xf013, flags DONT_FRAGMENT
  TCP: 34544 -> 6443
    seq. 0x97aa2d73 ack 0x6549f573
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:141785: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f0 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34544 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:141793: error-drop
  rx:host-eth0
02:04:13:141794: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 770

02:04:13:141744: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 96 snaplen 96 mac 66 net 80
      sec 0x5f35c658 nsec 0x99e2747 vlan 0 vlan_tpid 0
02:04:13:141761: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:141773: error-drop
  rx:host-eth0
02:04:13:141782: drop
  ethernet-input: l3 mac mismatch

Packet 771

02:04:13:141744: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x99e71c7 vlan 0 vlan_tpid 0
02:04:13:141761: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:141777: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xf283 dscp CS0 ecn NON_ECN
    fragment id 0xf014, flags DONT_FRAGMENT
  TCP: 34544 -> 6443
    seq. 0x97aa2d73 ack 0x6549f591
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:141785: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f0 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34544 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:141793: error-drop
  rx:host-eth0
02:04:13:141794: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 772

02:04:13:141744: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c658 nsec 0x9a0419f vlan 0 vlan_tpid 0
02:04:13:141761: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:141773: error-drop
  rx:host-eth0
02:04:13:141782: drop
  ethernet-input: l3 mac mismatch

Packet 773

02:04:13:141744: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x9a0a32b vlan 0 vlan_tpid 0
02:04:13:141761: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:141777: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xf282 dscp CS0 ecn NON_ECN
    fragment id 0xf015, flags DONT_FRAGMENT
  TCP: 34544 -> 6443
    seq. 0x97aa2d73 ack 0x6549f5a9
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:141785: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f0 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34544 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:141793: error-drop
  rx:host-eth0
02:04:13:141794: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 774

02:04:13:141744: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x9a10c0f vlan 0 vlan_tpid 0
02:04:13:141761: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:141773: error-drop
  rx:host-eth0
02:04:13:141782: drop
  ethernet-input: l3 mac mismatch

Packet 775

02:04:13:147111: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 274 snaplen 274 mac 66 net 80
      sec 0x5f35c658 nsec 0x9e820c3 vlan 0 vlan_tpid 0
02:04:13:147123: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:147130: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 260, checksum 0x7237 dscp CS0 ecn NON_ECN
    fragment id 0x6f91, flags DONT_FRAGMENT
  TCP: 34552 -> 6443
    seq. 0x72a7afb3 ack 0x6ce46a25
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:147134: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f8 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34552 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:13:147140: error-drop
  rx:host-eth0
02:04:13:147141: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 776

02:04:13:147111: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 274 snaplen 274 mac 66 net 80
      sec 0x5f35c658 nsec 0x9e8aa90 vlan 0 vlan_tpid 0
02:04:13:147123: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:147130: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 260, checksum 0x286f dscp CS0 ecn NON_ECN
    fragment id 0xb959, flags DONT_FRAGMENT
  TCP: 34556 -> 6443
    seq. 0x67b1d943 ack 0xdf4a5373
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:147134: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86fc 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34556 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:13:147140: error-drop
  rx:host-eth0
02:04:13:147141: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 777

02:04:13:151549: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c658 nsec 0xa21f612 vlan 0 vlan_tpid 0
02:04:13:152278: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:152292: error-drop
  rx:host-eth0
02:04:13:152303: drop
  ethernet-input: l3 mac mismatch

Packet 778

02:04:13:151549: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0xa225b40 vlan 0 vlan_tpid 0
02:04:13:152278: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:152296: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x7306 dscp CS0 ecn NON_ECN
    fragment id 0x6f92, flags DONT_FRAGMENT
  TCP: 34552 -> 6443
    seq. 0x72a7b083 ack 0x6ce46a3d
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:152307: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f8 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34552 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:152317: error-drop
  rx:host-eth0
02:04:13:152318: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 779

02:04:13:151549: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 106 snaplen 106 mac 66 net 80
      sec 0x5f35c658 nsec 0xa22d5e5 vlan 0 vlan_tpid 0
02:04:13:152278: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:152292: error-drop
  rx:host-eth0
02:04:13:152303: drop
  ethernet-input: l3 mac mismatch

Packet 780

02:04:13:151549: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0xa22f2cc vlan 0 vlan_tpid 0
02:04:13:152278: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:152296: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x7305 dscp CS0 ecn NON_ECN
    fragment id 0x6f93, flags DONT_FRAGMENT
  TCP: 34552 -> 6443
    seq. 0x72a7b083 ack 0x6ce46a65
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:152307: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f8 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34552 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:152317: error-drop
  rx:host-eth0
02:04:13:152318: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 781

02:04:13:151549: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c658 nsec 0xa2391bc vlan 0 vlan_tpid 0
02:04:13:152278: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:152292: error-drop
  rx:host-eth0
02:04:13:152303: drop
  ethernet-input: l3 mac mismatch

Packet 782

02:04:13:151549: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0xa23ca74 vlan 0 vlan_tpid 0
02:04:13:152278: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:152296: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x293e dscp CS0 ecn NON_ECN
    fragment id 0xb95a, flags DONT_FRAGMENT
  TCP: 34556 -> 6443
    seq. 0x67b1da13 ack 0xdf4a538b
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:152307: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86fc 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34556 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:152317: error-drop
  rx:host-eth0
02:04:13:152318: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 783

02:04:13:151549: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c658 nsec 0xa24c0fd vlan 0 vlan_tpid 0
02:04:13:152278: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:152292: error-drop
  rx:host-eth0
02:04:13:152303: drop
  ethernet-input: l3 mac mismatch

Packet 784

02:04:13:151549: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0xa24dffd vlan 0 vlan_tpid 0
02:04:13:152278: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:152296: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x293d dscp CS0 ecn NON_ECN
    fragment id 0xb95b, flags DONT_FRAGMENT
  TCP: 34556 -> 6443
    seq. 0x67b1da13 ack 0xdf4a53a3
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:152307: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86fc 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34556 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:152317: error-drop
  rx:host-eth0
02:04:13:152318: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 785

02:04:13:151549: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c658 nsec 0xa266558 vlan 0 vlan_tpid 0
02:04:13:152278: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:152292: error-drop
  rx:host-eth0
02:04:13:152303: drop
  ethernet-input: l3 mac mismatch

Packet 786

02:04:13:151549: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0xa268678 vlan 0 vlan_tpid 0
02:04:13:152278: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:152296: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x293c dscp CS0 ecn NON_ECN
    fragment id 0xb95c, flags DONT_FRAGMENT
  TCP: 34556 -> 6443
    seq. 0x67b1da13 ack 0xdf4a53bd
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:152307: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86fc 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34556 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:152317: error-drop
  rx:host-eth0
02:04:13:152318: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 787

02:04:13:151549: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c658 nsec 0xa285b38 vlan 0 vlan_tpid 0
02:04:13:152278: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:152292: error-drop
  rx:host-eth0
02:04:13:152303: drop
  ethernet-input: l3 mac mismatch

Packet 788

02:04:13:151549: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0xa287fa0 vlan 0 vlan_tpid 0
02:04:13:152278: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:152296: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x293b dscp CS0 ecn NON_ECN
    fragment id 0xb95d, flags DONT_FRAGMENT
  TCP: 34556 -> 6443
    seq. 0x67b1da13 ack 0xdf4a53d7
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:152307: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86fc 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34556 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:152317: error-drop
  rx:host-eth0
02:04:13:152318: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 789

02:04:13:151549: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 96 snaplen 96 mac 66 net 80
      sec 0x5f35c658 nsec 0xa2a0406 vlan 0 vlan_tpid 0
02:04:13:152278: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:152292: error-drop
  rx:host-eth0
02:04:13:152303: drop
  ethernet-input: l3 mac mismatch

Packet 790

02:04:13:151549: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0xa2a23af vlan 0 vlan_tpid 0
02:04:13:152278: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:152296: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x293a dscp CS0 ecn NON_ECN
    fragment id 0xb95e, flags DONT_FRAGMENT
  TCP: 34556 -> 6443
    seq. 0x67b1da13 ack 0xdf4a53f5
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:152307: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86fc 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34556 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:152317: error-drop
  rx:host-eth0
02:04:13:152318: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 791

02:04:13:185253: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0xc29f095 vlan 0 vlan_tpid 0
02:04:13:185264: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:185269: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xf281 dscp CS0 ecn NON_ECN
    fragment id 0xf016, flags DONT_FRAGMENT
  TCP: 34544 -> 6443
    seq. 0x97aa2d73 ack 0x6549f5aa
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:185274: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f0 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34544 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:185279: error-drop
  rx:host-eth0
02:04:13:185281: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 792

02:04:13:193121: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c658 nsec 0xca773fc vlan 0 vlan_tpid 0
02:04:13:193131: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:193141: error-drop
  rx:host-eth0
02:04:13:193146: drop
  ethernet-input: l3 mac mismatch

Packet 793

02:04:13:193121: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c658 nsec 0xca80690 vlan 0 vlan_tpid 0
02:04:13:193131: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:193141: error-drop
  rx:host-eth0
02:04:13:193146: drop
  ethernet-input: l3 mac mismatch

Packet 794

02:04:13:193121: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0xca859bb vlan 0 vlan_tpid 0
02:04:13:193131: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:193143: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x7304 dscp CS0 ecn NON_ECN
    fragment id 0x6f94, flags DONT_FRAGMENT
  TCP: 34552 -> 6443
    seq. 0x72a7b083 ack 0x6ce46a99
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:193148: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f8 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34552 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:193153: error-drop
  rx:host-eth0
02:04:13:193153: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 795

02:04:13:198855: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c658 nsec 0xcd9fe83 vlan 0 vlan_tpid 0
02:04:13:198879: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:199169: error-drop
  rx:host-eth0
02:04:13:199183: drop
  ethernet-input: l3 mac mismatch

Packet 796

02:04:13:198855: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0xcdaea21 vlan 0 vlan_tpid 0
02:04:13:198879: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:199174: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x7303 dscp CS0 ecn NON_ECN
    fragment id 0x6f95, flags DONT_FRAGMENT
  TCP: 34552 -> 6443
    seq. 0x72a7b083 ack 0x6ce46ab3
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:199188: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f8 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34552 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:199213: error-drop
  rx:host-eth0
02:04:13:199215: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 797

02:04:13:198855: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c658 nsec 0xcdbbb06 vlan 0 vlan_tpid 0
02:04:13:198879: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:199169: error-drop
  rx:host-eth0
02:04:13:199183: drop
  ethernet-input: l3 mac mismatch

Packet 798

02:04:13:198855: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0xcdc0a06 vlan 0 vlan_tpid 0
02:04:13:198879: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:199174: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x7302 dscp CS0 ecn NON_ECN
    fragment id 0x6f96, flags DONT_FRAGMENT
  TCP: 34552 -> 6443
    seq. 0x72a7b083 ack 0x6ce46acd
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:199188: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f8 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34552 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:199213: error-drop
  rx:host-eth0
02:04:13:199215: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 799

02:04:13:198855: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 122 snaplen 122 mac 66 net 80
      sec 0x5f35c658 nsec 0xcdc766d vlan 0 vlan_tpid 0
02:04:13:198879: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:199169: error-drop
  rx:host-eth0
02:04:13:199183: drop
  ethernet-input: l3 mac mismatch

Packet 800

02:04:13:198855: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0xcdcba65 vlan 0 vlan_tpid 0
02:04:13:198879: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:199174: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x7301 dscp CS0 ecn NON_ECN
    fragment id 0x6f97, flags DONT_FRAGMENT
  TCP: 34552 -> 6443
    seq. 0x72a7b083 ack 0x6ce46b05
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:199188: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f8 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34552 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:199213: error-drop
  rx:host-eth0
02:04:13:199215: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 801

02:04:13:198855: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c658 nsec 0xcdd2328 vlan 0 vlan_tpid 0
02:04:13:198879: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:199169: error-drop
  rx:host-eth0
02:04:13:199183: drop
  ethernet-input: l3 mac mismatch

Packet 802

02:04:13:198855: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0xcdd639f vlan 0 vlan_tpid 0
02:04:13:198879: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:199174: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x7300 dscp CS0 ecn NON_ECN
    fragment id 0x6f98, flags DONT_FRAGMENT
  TCP: 34552 -> 6443
    seq. 0x72a7b083 ack 0x6ce46b1d
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:199188: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f8 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34552 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:199213: error-drop
  rx:host-eth0
02:04:13:199215: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 803

02:04:13:198855: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c658 nsec 0xcde0a5f vlan 0 vlan_tpid 0
02:04:13:198879: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:199169: error-drop
  rx:host-eth0
02:04:13:199183: drop
  ethernet-input: l3 mac mismatch

Packet 804

02:04:13:198855: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0xcde5668 vlan 0 vlan_tpid 0
02:04:13:198879: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:199174: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x72ff dscp CS0 ecn NON_ECN
    fragment id 0x6f99, flags DONT_FRAGMENT
  TCP: 34552 -> 6443
    seq. 0x72a7b083 ack 0x6ce46b35
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:199188: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f8 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34552 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:199213: error-drop
  rx:host-eth0
02:04:13:199215: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 805

02:04:13:198855: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c658 nsec 0xcdec187 vlan 0 vlan_tpid 0
02:04:13:198879: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:199169: error-drop
  rx:host-eth0
02:04:13:199183: drop
  ethernet-input: l3 mac mismatch

Packet 806

02:04:13:198855: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0xcdf1679 vlan 0 vlan_tpid 0
02:04:13:198879: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:199174: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x72fe dscp CS0 ecn NON_ECN
    fragment id 0x6f9a, flags DONT_FRAGMENT
  TCP: 34552 -> 6443
    seq. 0x72a7b083 ack 0x6ce46b4f
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:199188: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f8 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34552 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:199213: error-drop
  rx:host-eth0
02:04:13:199215: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 807

02:04:13:198855: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c658 nsec 0xcdfae63 vlan 0 vlan_tpid 0
02:04:13:198879: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:199169: error-drop
  rx:host-eth0
02:04:13:199183: drop
  ethernet-input: l3 mac mismatch

Packet 808

02:04:13:198855: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0xce008de vlan 0 vlan_tpid 0
02:04:13:198879: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:199174: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x72fd dscp CS0 ecn NON_ECN
    fragment id 0x6f9b, flags DONT_FRAGMENT
  TCP: 34552 -> 6443
    seq. 0x72a7b083 ack 0x6ce46b69
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:199188: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f8 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34552 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:199213: error-drop
  rx:host-eth0
02:04:13:199215: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 809

02:04:13:198855: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c658 nsec 0xce1d24a vlan 0 vlan_tpid 0
02:04:13:198879: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:199169: error-drop
  rx:host-eth0
02:04:13:199183: drop
  ethernet-input: l3 mac mismatch

Packet 810

02:04:13:198855: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0xce2598d vlan 0 vlan_tpid 0
02:04:13:198879: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:199174: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x72fc dscp CS0 ecn NON_ECN
    fragment id 0x6f9c, flags DONT_FRAGMENT
  TCP: 34552 -> 6443
    seq. 0x72a7b083 ack 0x6ce46b83
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:199188: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f8 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34552 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:199213: error-drop
  rx:host-eth0
02:04:13:199215: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 811

02:04:13:198855: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c658 nsec 0xce53352 vlan 0 vlan_tpid 0
02:04:13:198879: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:199169: error-drop
  rx:host-eth0
02:04:13:199183: drop
  ethernet-input: l3 mac mismatch

Packet 812

02:04:13:198855: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0xce59a68 vlan 0 vlan_tpid 0
02:04:13:198879: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:199174: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x72fb dscp CS0 ecn NON_ECN
    fragment id 0x6f9d, flags DONT_FRAGMENT
  TCP: 34552 -> 6443
    seq. 0x72a7b083 ack 0x6ce46b9b
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:199188: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f8 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34552 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:199213: error-drop
  rx:host-eth0
02:04:13:199215: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 813

02:04:13:198855: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c658 nsec 0xce7514f vlan 0 vlan_tpid 0
02:04:13:198879: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:199169: error-drop
  rx:host-eth0
02:04:13:199183: drop
  ethernet-input: l3 mac mismatch

Packet 814

02:04:13:198855: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0xce7b5f9 vlan 0 vlan_tpid 0
02:04:13:198879: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:199174: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x72fa dscp CS0 ecn NON_ECN
    fragment id 0x6f9e, flags DONT_FRAGMENT
  TCP: 34552 -> 6443
    seq. 0x72a7b083 ack 0x6ce46bb3
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:199188: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f8 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34552 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:199213: error-drop
  rx:host-eth0
02:04:13:199215: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 815

02:04:13:198855: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c658 nsec 0xce9704e vlan 0 vlan_tpid 0
02:04:13:198879: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:199169: error-drop
  rx:host-eth0
02:04:13:199183: drop
  ethernet-input: l3 mac mismatch

Packet 816

02:04:13:198855: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0xce9d458 vlan 0 vlan_tpid 0
02:04:13:198879: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:199174: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x72f9 dscp CS0 ecn NON_ECN
    fragment id 0x6f9f, flags DONT_FRAGMENT
  TCP: 34552 -> 6443
    seq. 0x72a7b083 ack 0x6ce46bcd
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:199188: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f8 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34552 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:199213: error-drop
  rx:host-eth0
02:04:13:199215: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 817

02:04:13:198855: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c658 nsec 0xceb7d2b vlan 0 vlan_tpid 0
02:04:13:198879: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:199169: error-drop
  rx:host-eth0
02:04:13:199183: drop
  ethernet-input: l3 mac mismatch

Packet 818

02:04:13:198855: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0xcebed03 vlan 0 vlan_tpid 0
02:04:13:198879: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:199174: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x72f8 dscp CS0 ecn NON_ECN
    fragment id 0x6fa0, flags DONT_FRAGMENT
  TCP: 34552 -> 6443
    seq. 0x72a7b083 ack 0x6ce46be7
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:199188: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f8 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34552 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:199213: error-drop
  rx:host-eth0
02:04:13:199215: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 819

02:04:13:198855: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c658 nsec 0xceec63c vlan 0 vlan_tpid 0
02:04:13:198879: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:199169: error-drop
  rx:host-eth0
02:04:13:199183: drop
  ethernet-input: l3 mac mismatch

Packet 820

02:04:13:198855: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0xcef29a3 vlan 0 vlan_tpid 0
02:04:13:198879: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:199174: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x72f7 dscp CS0 ecn NON_ECN
    fragment id 0x6fa1, flags DONT_FRAGMENT
  TCP: 34552 -> 6443
    seq. 0x72a7b083 ack 0x6ce46c01
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:199188: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f8 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34552 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:199213: error-drop
  rx:host-eth0
02:04:13:199215: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 821

02:04:13:198855: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c658 nsec 0xcf0ffc6 vlan 0 vlan_tpid 0
02:04:13:198879: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:199169: error-drop
  rx:host-eth0
02:04:13:199183: drop
  ethernet-input: l3 mac mismatch

Packet 822

02:04:13:198855: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0xcf16a5e vlan 0 vlan_tpid 0
02:04:13:198879: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:199174: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x72f6 dscp CS0 ecn NON_ECN
    fragment id 0x6fa2, flags DONT_FRAGMENT
  TCP: 34552 -> 6443
    seq. 0x72a7b083 ack 0x6ce46c19
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:199188: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f8 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34552 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:199213: error-drop
  rx:host-eth0
02:04:13:199215: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 823

02:04:13:198855: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c658 nsec 0xcf330cd vlan 0 vlan_tpid 0
02:04:13:198879: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:199169: error-drop
  rx:host-eth0
02:04:13:199183: drop
  ethernet-input: l3 mac mismatch

Packet 824

02:04:13:198855: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0xcf3a21a vlan 0 vlan_tpid 0
02:04:13:198879: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:199174: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x72f5 dscp CS0 ecn NON_ECN
    fragment id 0x6fa3, flags DONT_FRAGMENT
  TCP: 34552 -> 6443
    seq. 0x72a7b083 ack 0x6ce46c31
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:199188: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f8 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34552 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:199213: error-drop
  rx:host-eth0
02:04:13:199215: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 825

02:04:13:198855: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c658 nsec 0xcf6d1be vlan 0 vlan_tpid 0
02:04:13:198879: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:199169: error-drop
  rx:host-eth0
02:04:13:199183: drop
  ethernet-input: l3 mac mismatch

Packet 826

02:04:13:198855: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0xcf745fd vlan 0 vlan_tpid 0
02:04:13:198879: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:199174: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x72f4 dscp CS0 ecn NON_ECN
    fragment id 0x6fa4, flags DONT_FRAGMENT
  TCP: 34552 -> 6443
    seq. 0x72a7b083 ack 0x6ce46c4b
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:199188: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f8 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34552 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:199213: error-drop
  rx:host-eth0
02:04:13:199215: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 827

02:04:13:198855: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c658 nsec 0xcf92854 vlan 0 vlan_tpid 0
02:04:13:198879: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:199169: error-drop
  rx:host-eth0
02:04:13:199183: drop
  ethernet-input: l3 mac mismatch

Packet 828

02:04:13:198855: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0xcf99b23 vlan 0 vlan_tpid 0
02:04:13:198879: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:199174: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x72f3 dscp CS0 ecn NON_ECN
    fragment id 0x6fa5, flags DONT_FRAGMENT
  TCP: 34552 -> 6443
    seq. 0x72a7b083 ack 0x6ce46c65
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:199188: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f8 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34552 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:199213: error-drop
  rx:host-eth0
02:04:13:199215: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 829

02:04:13:198855: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c658 nsec 0xcfb9cd6 vlan 0 vlan_tpid 0
02:04:13:198879: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:199169: error-drop
  rx:host-eth0
02:04:13:199183: drop
  ethernet-input: l3 mac mismatch

Packet 830

02:04:13:198855: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0xcfc1944 vlan 0 vlan_tpid 0
02:04:13:198879: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:199174: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x72f2 dscp CS0 ecn NON_ECN
    fragment id 0x6fa6, flags DONT_FRAGMENT
  TCP: 34552 -> 6443
    seq. 0x72a7b083 ack 0x6ce46c7f
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:199188: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f8 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34552 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:199213: error-drop
  rx:host-eth0
02:04:13:199215: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 831

02:04:13:198855: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c658 nsec 0xcfe212b vlan 0 vlan_tpid 0
02:04:13:198879: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:199169: error-drop
  rx:host-eth0
02:04:13:199183: drop
  ethernet-input: l3 mac mismatch

Packet 832

02:04:13:198855: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0xcfe8f66 vlan 0 vlan_tpid 0
02:04:13:198879: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:199174: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x72f1 dscp CS0 ecn NON_ECN
    fragment id 0x6fa7, flags DONT_FRAGMENT
  TCP: 34552 -> 6443
    seq. 0x72a7b083 ack 0x6ce46c97
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:199188: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f8 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34552 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:199213: error-drop
  rx:host-eth0
02:04:13:199215: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 833

02:04:13:198855: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0xd0134d8 vlan 0 vlan_tpid 0
02:04:13:198879: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:199169: error-drop
  rx:host-eth0
02:04:13:199183: drop
  ethernet-input: l3 mac mismatch

Packet 834

02:04:13:202727: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 74 snaplen 74 mac 66 net 80
      sec 0x5f35c658 nsec 0xd3d7066 vlan 0 vlan_tpid 0
02:04:13:202738: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:202744: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 60, checksum 0xe640 dscp CS0 ecn NON_ECN
    fragment id 0xfc4f, flags DONT_FRAGMENT
  TCP: 34588 -> 6443
    seq. 0xc95b4e05 ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 64240, checksum 0x0000
02:04:13:202751: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b871c 0302ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34588 -> 6443 tcp flags (valid) 02 rsvd 0
02:04:13:202759: error-drop
  rx:host-eth0
02:04:13:202759: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 835

02:04:13:202727: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 74 snaplen 74 mac 66 net 80
      sec 0x5f35c658 nsec 0xd3de624 vlan 0 vlan_tpid 0
02:04:13:202738: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:202749: error-drop
  rx:host-eth0
02:04:13:202757: drop
  ethernet-input: l3 mac mismatch

Packet 836

02:04:13:202727: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0xd3e22b9 vlan 0 vlan_tpid 0
02:04:13:202738: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:202744: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xe647 dscp CS0 ecn NON_ECN
    fragment id 0xfc50, flags DONT_FRAGMENT
  TCP: 34588 -> 6443
    seq. 0xc95b4e06 ack 0x16592ebb
    flags 0x10 ACK, tcp header: 32 bytes
    window 502, checksum 0x0000
02:04:13:202751: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b871c 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34588 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:202759: error-drop
  rx:host-eth0
02:04:13:202759: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 837

02:04:13:202727: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 468 snaplen 468 mac 66 net 80
      sec 0x5f35c658 nsec 0xd3ed608 vlan 0 vlan_tpid 0
02:04:13:202738: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:202744: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 454, checksum 0xf0ee dscp CS0 ecn NON_ECN
    fragment id 0xf017, flags DONT_FRAGMENT
  TCP: 34544 -> 6443
    seq. 0x97aa2d73 ack 0x6549f5aa
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:202751: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f0 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34544 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:13:202759: error-drop
  rx:host-eth0
02:04:13:202759: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 838

02:04:13:202727: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000001 len 54 snaplen 54 mac 66 net 80
      sec 0x5f35c658 nsec 0xd3f010f vlan 0 vlan_tpid 0
02:04:13:202738: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:202749: error-drop
  rx:host-eth0
02:04:13:202757: drop
  ethernet-input: l3 mac mismatch

Packet 839

02:04:13:205602: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c658 nsec 0xd659997 vlan 0 vlan_tpid 0
02:04:13:205613: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:205625: error-drop
  rx:host-eth0
02:04:13:205794: drop
  ethernet-input: l3 mac mismatch

Packet 840

02:04:13:205602: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0xd667752 vlan 0 vlan_tpid 0
02:04:13:205613: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:205621: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x2939 dscp CS0 ecn NON_ECN
    fragment id 0xb95f, flags DONT_FRAGMENT
  TCP: 34556 -> 6443
    seq. 0x67b1da13 ack 0xdf4a540f
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:205627: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86fc 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34556 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:205796: error-drop
  rx:host-eth0
02:04:13:205797: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 841

02:04:13:205602: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c658 nsec 0xd6f179d vlan 0 vlan_tpid 0
02:04:13:205613: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:205625: error-drop
  rx:host-eth0
02:04:13:205794: drop
  ethernet-input: l3 mac mismatch

Packet 842

02:04:13:205602: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0xd6fbd56 vlan 0 vlan_tpid 0
02:04:13:205613: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:205621: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x2938 dscp CS0 ecn NON_ECN
    fragment id 0xb960, flags DONT_FRAGMENT
  TCP: 34556 -> 6443
    seq. 0x67b1da13 ack 0xdf4a5429
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:205627: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86fc 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34556 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:205796: error-drop
  rx:host-eth0
02:04:13:205797: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 843

02:04:13:206860: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 130 snaplen 130 mac 66 net 80
      sec 0x5f35c658 nsec 0xd7bdfb4 vlan 0 vlan_tpid 0
02:04:13:206870: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:206877: error-drop
  rx:host-eth0
02:04:13:206882: drop
  ethernet-input: l3 mac mismatch

Packet 844

02:04:13:206860: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 100 snaplen 100 mac 66 net 80
      sec 0x5f35c658 nsec 0xd7c4c3d vlan 0 vlan_tpid 0
02:04:13:206870: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:206877: error-drop
  rx:host-eth0
02:04:13:206882: drop
  ethernet-input: l3 mac mismatch

Packet 845

02:04:13:206860: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 94 snaplen 94 mac 66 net 80
      sec 0x5f35c658 nsec 0xd7c7db1 vlan 0 vlan_tpid 0
02:04:13:206870: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:206877: error-drop
  rx:host-eth0
02:04:13:206882: drop
  ethernet-input: l3 mac mismatch

Packet 846

02:04:13:206860: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 94 snaplen 94 mac 66 net 80
      sec 0x5f35c658 nsec 0xd7caf7c vlan 0 vlan_tpid 0
02:04:13:206870: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:206877: error-drop
  rx:host-eth0
02:04:13:206882: drop
  ethernet-input: l3 mac mismatch

Packet 847

02:04:13:206860: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0xd7cc31a vlan 0 vlan_tpid 0
02:04:13:206870: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:206879: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x2937 dscp CS0 ecn NON_ECN
    fragment id 0xb961, flags DONT_FRAGMENT
  TCP: 34556 -> 6443
    seq. 0x67b1da13 ack 0xdf4a54a7
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:206884: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86fc 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34556 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:206889: error-drop
  rx:host-eth0
02:04:13:206889: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 848

02:04:13:206860: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 98 snaplen 98 mac 66 net 80
      sec 0x5f35c658 nsec 0xd7ccf9e vlan 0 vlan_tpid 0
02:04:13:206870: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:206877: error-drop
  rx:host-eth0
02:04:13:206882: drop
  ethernet-input: l3 mac mismatch

Packet 849

02:04:13:206860: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 94 snaplen 94 mac 66 net 80
      sec 0x5f35c658 nsec 0xd7cfceb vlan 0 vlan_tpid 0
02:04:13:206870: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:206877: error-drop
  rx:host-eth0
02:04:13:206882: drop
  ethernet-input: l3 mac mismatch

Packet 850

02:04:13:206860: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 96 snaplen 96 mac 66 net 80
      sec 0x5f35c658 nsec 0xd7d1ac6 vlan 0 vlan_tpid 0
02:04:13:206870: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:206877: error-drop
  rx:host-eth0
02:04:13:206882: drop
  ethernet-input: l3 mac mismatch

Packet 851

02:04:13:206860: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0xd7d6048 vlan 0 vlan_tpid 0
02:04:13:206870: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:206879: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x2936 dscp CS0 ecn NON_ECN
    fragment id 0xb962, flags DONT_FRAGMENT
  TCP: 34556 -> 6443
    seq. 0x67b1da13 ack 0xdf4a551d
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:206884: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86fc 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34556 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:206889: error-drop
  rx:host-eth0
02:04:13:206889: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 852

02:04:13:206860: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c658 nsec 0xd7d85a2 vlan 0 vlan_tpid 0
02:04:13:206870: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:206877: error-drop
  rx:host-eth0
02:04:13:206882: drop
  ethernet-input: l3 mac mismatch

Packet 853

02:04:13:206860: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0xd7da358 vlan 0 vlan_tpid 0
02:04:13:206870: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:206879: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x2935 dscp CS0 ecn NON_ECN
    fragment id 0xb963, flags DONT_FRAGMENT
  TCP: 34556 -> 6443
    seq. 0x67b1da13 ack 0xdf4a5535
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:206884: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86fc 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34556 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:206889: error-drop
  rx:host-eth0
02:04:13:206889: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 854

02:04:13:206860: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0xd7dd424 vlan 0 vlan_tpid 0
02:04:13:206870: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:206877: error-drop
  rx:host-eth0
02:04:13:206882: drop
  ethernet-input: l3 mac mismatch

Packet 855

02:04:13:240597: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0xf805a8f vlan 0 vlan_tpid 0
02:04:13:240606: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:240612: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x72f0 dscp CS0 ecn NON_ECN
    fragment id 0x6fa8, flags DONT_FRAGMENT
  TCP: 34552 -> 6443
    seq. 0x72a7b083 ack 0x6ce46c98
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:240616: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f8 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34552 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:240621: error-drop
  rx:host-eth0
02:04:13:240622: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 856

02:04:13:252922: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x10376995 vlan 0 vlan_tpid 0
02:04:13:252929: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:252933: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x2934 dscp CS0 ecn NON_ECN
    fragment id 0xb964, flags DONT_FRAGMENT
  TCP: 34556 -> 6443
    seq. 0x67b1da13 ack 0xdf4a5536
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:252935: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86fc 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34556 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:252940: error-drop
  rx:host-eth0
02:04:13:252941: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 857

02:04:13:258305: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 342 snaplen 342 mac 66 net 80
      sec 0x5f35c658 nsec 0x108eca02 vlan 0 vlan_tpid 0
02:04:13:258315: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:258323: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 328, checksum 0x71db dscp CS0 ecn NON_ECN
    fragment id 0x6fa9, flags DONT_FRAGMENT
  TCP: 34552 -> 6443
    seq. 0x72a7b083 ack 0x6ce46c98
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:258330: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86f8 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34552 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:13:258337: error-drop
  rx:host-eth0
02:04:13:258338: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 858

02:04:13:258305: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 74 snaplen 74 mac 66 net 80
      sec 0x5f35c658 nsec 0x108f1296 vlan 0 vlan_tpid 0
02:04:13:258315: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:258323: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 60, checksum 0x83ad dscp CS0 ecn NON_ECN
    fragment id 0x5ee3, flags DONT_FRAGMENT
  TCP: 34592 -> 6443
    seq. 0xfc6ede43 ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 64240, checksum 0x0000
02:04:13:258330: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8720 0302ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34592 -> 6443 tcp flags (valid) 02 rsvd 0
02:04:13:258337: error-drop
  rx:host-eth0
02:04:13:258338: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 859

02:04:13:258305: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000001 len 54 snaplen 54 mac 66 net 80
      sec 0x5f35c658 nsec 0x108f3a4f vlan 0 vlan_tpid 0
02:04:13:258315: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:258328: error-drop
  rx:host-eth0
02:04:13:258336: drop
  ethernet-input: l3 mac mismatch

Packet 860

02:04:13:258305: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 74 snaplen 74 mac 66 net 80
      sec 0x5f35c658 nsec 0x108f6c58 vlan 0 vlan_tpid 0
02:04:13:258315: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:258328: error-drop
  rx:host-eth0
02:04:13:258336: drop
  ethernet-input: l3 mac mismatch

Packet 861

02:04:13:258305: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x108fa33d vlan 0 vlan_tpid 0
02:04:13:258315: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:258323: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x83b4 dscp CS0 ecn NON_ECN
    fragment id 0x5ee4, flags DONT_FRAGMENT
  TCP: 34592 -> 6443
    seq. 0xfc6ede44 ack 0x769bbe72
    flags 0x10 ACK, tcp header: 32 bytes
    window 502, checksum 0x0000
02:04:13:258330: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8720 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34592 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:258337: error-drop
  rx:host-eth0
02:04:13:258338: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 862

02:04:13:263188: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 305 snaplen 305 mac 66 net 80
      sec 0x5f35c658 nsec 0x10d58ff0 vlan 0 vlan_tpid 0
02:04:13:263197: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:263237: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 291, checksum 0xe557 dscp CS0 ecn NON_ECN
    fragment id 0xfc51, flags DONT_FRAGMENT
  TCP: 34588 -> 6443
    seq. 0xc95b4e06 ack 0x16592ebb
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 502, checksum 0x0000
02:04:13:263243: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b871c 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34588 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:13:263250: error-drop
  rx:host-eth0
02:04:13:263250: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 863

02:04:13:263188: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x10d60df7 vlan 0 vlan_tpid 0
02:04:13:263197: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:263242: error-drop
  rx:host-eth0
02:04:13:263248: drop
  ethernet-input: l3 mac mismatch

Packet 864

02:04:13:269314: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 1647 snaplen 1647 mac 66 net 80
      sec 0x5f35c658 nsec 0x111accc2 vlan 0 vlan_tpid 0
02:04:13:269325: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:269339: error-drop
  rx:host-eth0
02:04:13:269347: drop
  ethernet-input: l3 mac mismatch

Packet 865

02:04:13:269314: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x111b4562 vlan 0 vlan_tpid 0
02:04:13:269325: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:269332: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xe645 dscp CS0 ecn NON_ECN
    fragment id 0xfc52, flags DONT_FRAGMENT
  TCP: 34588 -> 6443
    seq. 0xc95b4ef5 ack 0x165934e8
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:269341: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b871c 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34588 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:269349: error-drop
  rx:host-eth0
02:04:13:269349: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 866

02:04:13:269314: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 74 snaplen 74 mac 66 net 80
      sec 0x5f35c658 nsec 0x111fb37c vlan 0 vlan_tpid 0
02:04:13:269325: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:269332: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 60, checksum 0xe2f8 dscp CS0 ecn NON_ECN
    fragment id 0xff97, flags DONT_FRAGMENT
  TCP: 34596 -> 6443
    seq. 0x8125821f ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 64240, checksum 0x0000
02:04:13:269341: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8724 0302ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34596 -> 6443 tcp flags (valid) 02 rsvd 0
02:04:13:269349: error-drop
  rx:host-eth0
02:04:13:269349: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 867

02:04:13:269314: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 74 snaplen 74 mac 66 net 80
      sec 0x5f35c658 nsec 0x1120269a vlan 0 vlan_tpid 0
02:04:13:269325: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:269339: error-drop
  rx:host-eth0
02:04:13:269347: drop
  ethernet-input: l3 mac mismatch

Packet 868

02:04:13:269314: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x11206222 vlan 0 vlan_tpid 0
02:04:13:269325: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:269332: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xe2ff dscp CS0 ecn NON_ECN
    fragment id 0xff98, flags DONT_FRAGMENT
  TCP: 34596 -> 6443
    seq. 0x81258220 ack 0x5c066364
    flags 0x10 ACK, tcp header: 32 bytes
    window 502, checksum 0x0000
02:04:13:269341: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8724 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34596 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:269349: error-drop
  rx:host-eth0
02:04:13:269349: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 869

02:04:13:269314: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 342 snaplen 342 mac 66 net 80
      sec 0x5f35c658 nsec 0x11219390 vlan 0 vlan_tpid 0
02:04:13:269325: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:269332: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 328, checksum 0x281f dscp CS0 ecn NON_ECN
    fragment id 0xb965, flags DONT_FRAGMENT
  TCP: 34556 -> 6443
    seq. 0x67b1da13 ack 0xdf4a5536
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:269341: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b86fc 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34556 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:13:269349: error-drop
  rx:host-eth0
02:04:13:269349: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 870

02:04:13:269314: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000001 len 54 snaplen 54 mac 66 net 80
      sec 0x5f35c658 nsec 0x1121c0d8 vlan 0 vlan_tpid 0
02:04:13:269325: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:269339: error-drop
  rx:host-eth0
02:04:13:269347: drop
  ethernet-input: l3 mac mismatch

Packet 871

02:04:13:321606: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 305 snaplen 305 mac 66 net 80
      sec 0x5f35c658 nsec 0x1451636d vlan 0 vlan_tpid 0
02:04:13:321614: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:321619: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 291, checksum 0x82c4 dscp CS0 ecn NON_ECN
    fragment id 0x5ee5, flags DONT_FRAGMENT
  TCP: 34592 -> 6443
    seq. 0xfc6ede44 ack 0x769bbe72
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 502, checksum 0x0000
02:04:13:321623: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8720 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34592 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:13:321629: error-drop
  rx:host-eth0
02:04:13:321629: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 872

02:04:13:321606: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x1451acc9 vlan 0 vlan_tpid 0
02:04:13:321614: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:321622: error-drop
  rx:host-eth0
02:04:13:321627: drop
  ethernet-input: l3 mac mismatch

Packet 873

02:04:13:324844: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 1647 snaplen 1647 mac 66 net 80
      sec 0x5f35c658 nsec 0x1480ee5d vlan 0 vlan_tpid 0
02:04:13:324851: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:324855: error-drop
  rx:host-eth0
02:04:13:324858: drop
  ethernet-input: l3 mac mismatch

Packet 874

02:04:13:324844: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x1481618f vlan 0 vlan_tpid 0
02:04:13:324851: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:324856: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x83b2 dscp CS0 ecn NON_ECN
    fragment id 0x5ee6, flags DONT_FRAGMENT
  TCP: 34592 -> 6443
    seq. 0xfc6edf33 ack 0x769bc49f
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:324860: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8720 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34592 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:324863: error-drop
  rx:host-eth0
02:04:13:324864: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 875

02:04:13:329316: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 305 snaplen 305 mac 66 net 80
      sec 0x5f35c658 nsec 0x14c480c0 vlan 0 vlan_tpid 0
02:04:13:329325: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:329330: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 291, checksum 0xe20f dscp CS0 ecn NON_ECN
    fragment id 0xff99, flags DONT_FRAGMENT
  TCP: 34596 -> 6443
    seq. 0x81258220 ack 0x5c066364
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 502, checksum 0x0000
02:04:13:329335: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8724 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34596 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:13:329341: error-drop
  rx:host-eth0
02:04:13:329341: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 876

02:04:13:329316: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x14c4ccee vlan 0 vlan_tpid 0
02:04:13:329325: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:329334: error-drop
  rx:host-eth0
02:04:13:329339: drop
  ethernet-input: l3 mac mismatch

Packet 877

02:04:13:331619: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 1647 snaplen 1647 mac 66 net 80
      sec 0x5f35c658 nsec 0x14e76498 vlan 0 vlan_tpid 0
02:04:13:331628: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:331634: error-drop
  rx:host-eth0
02:04:13:331639: drop
  ethernet-input: l3 mac mismatch

Packet 878

02:04:13:331619: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x14e7d608 vlan 0 vlan_tpid 0
02:04:13:331628: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:331636: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xe2fd dscp CS0 ecn NON_ECN
    fragment id 0xff9a, flags DONT_FRAGMENT
  TCP: 34596 -> 6443
    seq. 0x8125830f ack 0x5c066991
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:331641: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8724 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34596 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:331645: error-drop
  rx:host-eth0
02:04:13:331646: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 879

02:04:13:338078: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 1723 snaplen 1723 mac 66 net 80
      sec 0x5f35c658 nsec 0x154d3a05 vlan 0 vlan_tpid 0
02:04:13:338085: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:338092: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 1709, checksum 0xdfcb dscp CS0 ecn NON_ECN
    fragment id 0xfc53, flags DONT_FRAGMENT
  TCP: 34588 -> 6443
    seq. 0xc95b4ef5 ack 0x165934e8
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:338098: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b871c 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34588 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:13:338105: error-drop
  rx:host-eth0
02:04:13:338106: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 880

02:04:13:338078: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x154d8382 vlan 0 vlan_tpid 0
02:04:13:338085: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:338096: error-drop
  rx:host-eth0
02:04:13:338104: drop
  ethernet-input: l3 mac mismatch

Packet 881

02:04:13:349801: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 247 snaplen 247 mac 66 net 80
      sec 0x5f35c658 nsec 0x15f9c8b1 vlan 0 vlan_tpid 0
02:04:13:349808: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:349813: error-drop
  rx:host-eth0
02:04:13:349817: drop
  ethernet-input: l3 mac mismatch

Packet 882

02:04:13:349801: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x15fa2837 vlan 0 vlan_tpid 0
02:04:13:349808: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:349815: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xe642 dscp CS0 ecn NON_ECN
    fragment id 0xfc55, flags DONT_FRAGMENT
  TCP: 34588 -> 6443
    seq. 0xc95b556e ack 0x1659359d
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:349819: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b871c 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34588 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:349822: error-drop
  rx:host-eth0
02:04:13:349823: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 883

02:04:13:404547: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 1723 snaplen 1723 mac 66 net 80
      sec 0x5f35c658 nsec 0x19352f15 vlan 0 vlan_tpid 0
02:04:13:404562: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:404682: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 1709, checksum 0xdc83 dscp CS0 ecn NON_ECN
    fragment id 0xff9b, flags DONT_FRAGMENT
  TCP: 34596 -> 6443
    seq. 0x8125830f ack 0x5c066991
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:404688: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8724 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34596 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:13:404693: error-drop
  rx:host-eth0
02:04:13:404694: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 884

02:04:13:404547: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x193595c0 vlan 0 vlan_tpid 0
02:04:13:404562: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:404679: error-drop
  rx:host-eth0
02:04:13:404686: drop
  ethernet-input: l3 mac mismatch

Packet 885

02:04:13:404547: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 1718 snaplen 1718 mac 66 net 80
      sec 0x5f35c658 nsec 0x193616d5 vlan 0 vlan_tpid 0
02:04:13:404562: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:404682: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 1704, checksum 0x7d3d dscp CS0 ecn NON_ECN
    fragment id 0x5ee7, flags DONT_FRAGMENT
  TCP: 34592 -> 6443
    seq. 0xfc6edf33 ack 0x769bc49f
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:404688: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8720 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34592 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:13:404693: error-drop
  rx:host-eth0
02:04:13:404694: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 886

02:04:13:404547: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x193631b1 vlan 0 vlan_tpid 0
02:04:13:404562: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:404679: error-drop
  rx:host-eth0
02:04:13:404686: drop
  ethernet-input: l3 mac mismatch

Packet 887

02:04:13:413509: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 291 snaplen 291 mac 66 net 80
      sec 0x5f35c658 nsec 0x19c4ea71 vlan 0 vlan_tpid 0
02:04:13:413518: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:413527: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 277, checksum 0xe560 dscp CS0 ecn NON_ECN
    fragment id 0xfc56, flags DONT_FRAGMENT
  TCP: 34588 -> 6443
    seq. 0xc95b556e ack 0x1659359d
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:413548: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b871c 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34588 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:13:413556: error-drop
  rx:host-eth0
02:04:13:413556: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 888

02:04:13:413509: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x19c51f3f vlan 0 vlan_tpid 0
02:04:13:413518: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:413546: error-drop
  rx:host-eth0
02:04:13:413553: drop
  ethernet-input: l3 mac mismatch

Packet 889

02:04:13:436247: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 116 snaplen 116 mac 66 net 80
      sec 0x5f35c658 nsec 0x1b2a63e3 vlan 0 vlan_tpid 0
02:04:13:436258: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:436265: error-drop
  rx:host-eth0
02:04:13:436340: drop
  ethernet-input: l3 mac mismatch

Packet 890

02:04:13:436247: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x1b2abcf9 vlan 0 vlan_tpid 0
02:04:13:436258: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:436268: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xe640 dscp CS0 ecn NON_ECN
    fragment id 0xfc57, flags DONT_FRAGMENT
  TCP: 34588 -> 6443
    seq. 0xc95b564f ack 0x165935cf
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:436343: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b871c 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34588 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:436347: error-drop
  rx:host-eth0
02:04:13:436348: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 891

02:04:13:450938: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 247 snaplen 247 mac 66 net 80
      sec 0x5f35c658 nsec 0x1bf680b4 vlan 0 vlan_tpid 0
02:04:13:450949: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:450959: error-drop
  rx:host-eth0
02:04:13:450965: drop
  ethernet-input: l3 mac mismatch

Packet 892

02:04:13:450938: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x1bf6fc29 vlan 0 vlan_tpid 0
02:04:13:450949: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:450962: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xe2fa dscp CS0 ecn NON_ECN
    fragment id 0xff9d, flags DONT_FRAGMENT
  TCP: 34596 -> 6443
    seq. 0x81258988 ack 0x5c066a46
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:450967: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8724 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34596 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:450973: error-drop
  rx:host-eth0
02:04:13:450973: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 893

02:04:13:450938: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 247 snaplen 247 mac 66 net 80
      sec 0x5f35c658 nsec 0x1bf7aecb vlan 0 vlan_tpid 0
02:04:13:450949: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:450959: error-drop
  rx:host-eth0
02:04:13:450965: drop
  ethernet-input: l3 mac mismatch

Packet 894

02:04:13:450938: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x1bf7ecfd vlan 0 vlan_tpid 0
02:04:13:450949: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:450962: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x83af dscp CS0 ecn NON_ECN
    fragment id 0x5ee9, flags DONT_FRAGMENT
  TCP: 34592 -> 6443
    seq. 0xfc6ee5a7 ack 0x769bc554
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:450967: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8720 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34592 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:450973: error-drop
  rx:host-eth0
02:04:13:450973: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 895

02:04:13:496361: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 275 snaplen 275 mac 66 net 80
      sec 0x5f35c658 nsec 0x1eb724a6 vlan 0 vlan_tpid 0
02:04:13:496370: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:496382: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 261, checksum 0xe56e dscp CS0 ecn NON_ECN
    fragment id 0xfc58, flags DONT_FRAGMENT
  TCP: 34588 -> 6443
    seq. 0xc95b564f ack 0x165935cf
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:496387: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b871c 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34588 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:13:496393: error-drop
  rx:host-eth0
02:04:13:496394: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 896

02:04:13:496361: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c658 nsec 0x1ebd1167 vlan 0 vlan_tpid 0
02:04:13:496370: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:496379: error-drop
  rx:host-eth0
02:04:13:496386: drop
  ethernet-input: l3 mac mismatch

Packet 897

02:04:13:496361: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x1ebd479b vlan 0 vlan_tpid 0
02:04:13:496370: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:496382: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xe63e dscp CS0 ecn NON_ECN
    fragment id 0xfc59, flags DONT_FRAGMENT
  TCP: 34588 -> 6443
    seq. 0xc95b5720 ack 0x165935e9
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:496387: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b871c 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34588 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:496393: error-drop
  rx:host-eth0
02:04:13:496394: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 898

02:04:13:496361: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 104 snaplen 104 mac 66 net 80
      sec 0x5f35c658 nsec 0x1ebf2f77 vlan 0 vlan_tpid 0
02:04:13:496370: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:496379: error-drop
  rx:host-eth0
02:04:13:496386: drop
  ethernet-input: l3 mac mismatch

Packet 899

02:04:13:496361: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x1ebf5753 vlan 0 vlan_tpid 0
02:04:13:496370: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:496382: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xe63d dscp CS0 ecn NON_ECN
    fragment id 0xfc5a, flags DONT_FRAGMENT
  TCP: 34588 -> 6443
    seq. 0xc95b5720 ack 0x1659360f
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:496387: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b871c 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34588 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:496393: error-drop
  rx:host-eth0
02:04:13:496394: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 900

02:04:13:507016: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 192 snaplen 192 mac 66 net 80
      sec 0x5f35c658 nsec 0x1f5d28d3 vlan 0 vlan_tpid 0
02:04:13:507026: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:507035: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 178, checksum 0xe27b dscp CS0 ecn NON_ECN
    fragment id 0xff9e, flags DONT_FRAGMENT
  TCP: 34596 -> 6443
    seq. 0x81258988 ack 0x5c066a46
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:507040: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8724 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34596 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:13:507045: error-drop
  rx:host-eth0
02:04:13:507046: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 901

02:04:13:507016: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x1f5d6fe3 vlan 0 vlan_tpid 0
02:04:13:507026: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:507033: error-drop
  rx:host-eth0
02:04:13:507038: drop
  ethernet-input: l3 mac mismatch

Packet 902

02:04:13:507016: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 215 snaplen 215 mac 66 net 80
      sec 0x5f35c658 nsec 0x1f5e12fc vlan 0 vlan_tpid 0
02:04:13:507026: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:507035: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 201, checksum 0x8319 dscp CS0 ecn NON_ECN
    fragment id 0x5eea, flags DONT_FRAGMENT
  TCP: 34592 -> 6443
    seq. 0xfc6ee5a7 ack 0x769bc554
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:507040: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8720 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34592 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:13:507045: error-drop
  rx:host-eth0
02:04:13:507046: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 903

02:04:13:507016: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x1f5e2e34 vlan 0 vlan_tpid 0
02:04:13:507026: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:507033: error-drop
  rx:host-eth0
02:04:13:507038: drop
  ethernet-input: l3 mac mismatch

Packet 904

02:04:13:511893: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 165 snaplen 165 mac 66 net 80
      sec 0x5f35c658 nsec 0x1f9f188a vlan 0 vlan_tpid 0
02:04:13:511908: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:511918: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 151, checksum 0xe295 dscp CS0 ecn NON_ECN
    fragment id 0xff9f, flags DONT_FRAGMENT
  TCP: 34596 -> 6443
    seq. 0x81258a06 ack 0x5c066a46
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:511962: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8724 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34596 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:13:511972: error-drop
  rx:host-eth0
02:04:13:511972: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 905

02:04:13:511893: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x1f9f64b6 vlan 0 vlan_tpid 0
02:04:13:511908: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:511959: error-drop
  rx:host-eth0
02:04:13:511969: drop
  ethernet-input: l3 mac mismatch

Packet 906

02:04:13:511893: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 142 snaplen 142 mac 66 net 80
      sec 0x5f35c658 nsec 0x1f9fe2d3 vlan 0 vlan_tpid 0
02:04:13:511908: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:511918: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 128, checksum 0x8361 dscp CS0 ecn NON_ECN
    fragment id 0x5eeb, flags DONT_FRAGMENT
  TCP: 34592 -> 6443
    seq. 0xfc6ee63c ack 0x769bc554
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:511962: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8720 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34592 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:13:511972: error-drop
  rx:host-eth0
02:04:13:511972: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 907

02:04:13:511893: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x1f9fff7e vlan 0 vlan_tpid 0
02:04:13:511908: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:511959: error-drop
  rx:host-eth0
02:04:13:511969: drop
  ethernet-input: l3 mac mismatch

Packet 908

02:04:13:511893: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 96 snaplen 96 mac 66 net 80
      sec 0x5f35c658 nsec 0x1faaf42e vlan 0 vlan_tpid 0
02:04:13:511908: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:511959: error-drop
  rx:host-eth0
02:04:13:511969: drop
  ethernet-input: l3 mac mismatch

Packet 909

02:04:13:511893: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c658 nsec 0x1fab08ec vlan 0 vlan_tpid 0
02:04:13:511908: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:511959: error-drop
  rx:host-eth0
02:04:13:511969: drop
  ethernet-input: l3 mac mismatch

Packet 910

02:04:13:511893: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x1fab3ff0 vlan 0 vlan_tpid 0
02:04:13:511908: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:511918: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x83ac dscp CS0 ecn NON_ECN
    fragment id 0x5eec, flags DONT_FRAGMENT
  TCP: 34592 -> 6443
    seq. 0xfc6ee688 ack 0x769bc56c
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:511962: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8720 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34592 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:511972: error-drop
  rx:host-eth0
02:04:13:511972: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 911

02:04:13:511893: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x1fab476d vlan 0 vlan_tpid 0
02:04:13:511908: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:511918: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xe2f7 dscp CS0 ecn NON_ECN
    fragment id 0xffa0, flags DONT_FRAGMENT
  TCP: 34596 -> 6443
    seq. 0x81258a69 ack 0x5c066a64
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:511962: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8724 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34596 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:511972: error-drop
  rx:host-eth0
02:04:13:511972: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 912

02:04:13:511893: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 108 snaplen 108 mac 66 net 80
      sec 0x5f35c658 nsec 0x1fabbaec vlan 0 vlan_tpid 0
02:04:13:511908: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:511959: error-drop
  rx:host-eth0
02:04:13:511969: drop
  ethernet-input: l3 mac mismatch

Packet 913

02:04:13:511893: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x1fabd380 vlan 0 vlan_tpid 0
02:04:13:511908: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:511918: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xe2f6 dscp CS0 ecn NON_ECN
    fragment id 0xffa1, flags DONT_FRAGMENT
  TCP: 34596 -> 6443
    seq. 0x81258a69 ack 0x5c066a8e
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:511962: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8724 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34596 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:511972: error-drop
  rx:host-eth0
02:04:13:511972: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 914

02:04:13:513023: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 114 snaplen 114 mac 66 net 80
      sec 0x5f35c658 nsec 0x1fad8631 vlan 0 vlan_tpid 0
02:04:13:513031: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:513036: error-drop
  rx:host-eth0
02:04:13:513040: drop
  ethernet-input: l3 mac mismatch

Packet 915

02:04:13:513023: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x1fada903 vlan 0 vlan_tpid 0
02:04:13:513031: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:513038: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x83ab dscp CS0 ecn NON_ECN
    fragment id 0x5eed, flags DONT_FRAGMENT
  TCP: 34592 -> 6443
    seq. 0xfc6ee688 ack 0x769bc59c
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:513042: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8720 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34592 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:513046: error-drop
  rx:host-eth0
02:04:13:513047: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 916

02:04:13:560672: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 274 snaplen 274 mac 66 net 80
      sec 0x5f35c658 nsec 0x2286f5a1 vlan 0 vlan_tpid 0
02:04:13:560681: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:560691: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 260, checksum 0xe56c dscp CS0 ecn NON_ECN
    fragment id 0xfc5b, flags DONT_FRAGMENT
  TCP: 34588 -> 6443
    seq. 0xc95b5720 ack 0x1659360f
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:560696: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b871c 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34588 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:13:560700: error-drop
  rx:host-eth0
02:04:13:560701: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 917

02:04:13:560672: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 96 snaplen 96 mac 66 net 80
      sec 0x5f35c658 nsec 0x228d8c91 vlan 0 vlan_tpid 0
02:04:13:560681: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:560688: error-drop
  rx:host-eth0
02:04:13:560694: drop
  ethernet-input: l3 mac mismatch

Packet 918

02:04:13:560672: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x228ddb45 vlan 0 vlan_tpid 0
02:04:13:560681: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:560691: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xe63b dscp CS0 ecn NON_ECN
    fragment id 0xfc5c, flags DONT_FRAGMENT
  TCP: 34588 -> 6443
    seq. 0xc95b57f0 ack 0x1659362d
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:560696: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b871c 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34588 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:560700: error-drop
  rx:host-eth0
02:04:13:560701: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 919

02:04:13:560672: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 100 snaplen 100 mac 66 net 80
      sec 0x5f35c658 nsec 0x228e69bd vlan 0 vlan_tpid 0
02:04:13:560681: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:560688: error-drop
  rx:host-eth0
02:04:13:560694: drop
  ethernet-input: l3 mac mismatch

Packet 920

02:04:13:560672: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x228e85b3 vlan 0 vlan_tpid 0
02:04:13:560681: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:560691: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xe63a dscp CS0 ecn NON_ECN
    fragment id 0xfc5d, flags DONT_FRAGMENT
  TCP: 34588 -> 6443
    seq. 0xc95b57f0 ack 0x1659364f
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:560696: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b871c 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34588 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:560700: error-drop
  rx:host-eth0
02:04:13:560701: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 921

02:04:13:571671: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 275 snaplen 275 mac 66 net 80
      sec 0x5f35c658 nsec 0x232ad1e8 vlan 0 vlan_tpid 0
02:04:13:571736: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:571747: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 261, checksum 0xe224 dscp CS0 ecn NON_ECN
    fragment id 0xffa2, flags DONT_FRAGMENT
  TCP: 34596 -> 6443
    seq. 0x81258a69 ack 0x5c066a8e
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:571752: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8724 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34596 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:13:571759: error-drop
  rx:host-eth0
02:04:13:571760: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 922

02:04:13:571671: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x232b0baf vlan 0 vlan_tpid 0
02:04:13:571736: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:571744: error-drop
  rx:host-eth0
02:04:13:571751: drop
  ethernet-input: l3 mac mismatch

Packet 923

02:04:13:571671: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 275 snaplen 275 mac 66 net 80
      sec 0x5f35c658 nsec 0x232b6f9d vlan 0 vlan_tpid 0
02:04:13:571736: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:571747: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 261, checksum 0x82d9 dscp CS0 ecn NON_ECN
    fragment id 0x5eee, flags DONT_FRAGMENT
  TCP: 34592 -> 6443
    seq. 0xfc6ee688 ack 0x769bc59c
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:571752: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8720 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34592 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:13:571759: error-drop
  rx:host-eth0
02:04:13:571760: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 924

02:04:13:571671: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x232b85f9 vlan 0 vlan_tpid 0
02:04:13:571736: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:571744: error-drop
  rx:host-eth0
02:04:13:571751: drop
  ethernet-input: l3 mac mismatch

Packet 925

02:04:13:571671: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c658 nsec 0x23388a11 vlan 0 vlan_tpid 0
02:04:13:571736: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:571744: error-drop
  rx:host-eth0
02:04:13:571751: drop
  ethernet-input: l3 mac mismatch

Packet 926

02:04:13:571671: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x2338c79a vlan 0 vlan_tpid 0
02:04:13:571736: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:571747: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x83a9 dscp CS0 ecn NON_ECN
    fragment id 0x5eef, flags DONT_FRAGMENT
  TCP: 34592 -> 6443
    seq. 0xfc6ee759 ack 0x769bc5b4
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:571752: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8720 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34592 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:571759: error-drop
  rx:host-eth0
02:04:13:571760: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 927

02:04:13:572966: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c658 nsec 0x233d44da vlan 0 vlan_tpid 0
02:04:13:572978: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:572987: error-drop
  rx:host-eth0
02:04:13:572994: drop
  ethernet-input: l3 mac mismatch

Packet 928

02:04:13:572966: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x233d7303 vlan 0 vlan_tpid 0
02:04:13:572978: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:572989: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xe2f4 dscp CS0 ecn NON_ECN
    fragment id 0xffa3, flags DONT_FRAGMENT
  TCP: 34596 -> 6443
    seq. 0x81258b3a ack 0x5c066aa6
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:572996: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8724 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34596 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:573004: error-drop
  rx:host-eth0
02:04:13:573005: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 929

02:04:13:572966: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c658 nsec 0x233fed2c vlan 0 vlan_tpid 0
02:04:13:572978: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:572987: error-drop
  rx:host-eth0
02:04:13:572994: drop
  ethernet-input: l3 mac mismatch

Packet 930

02:04:13:572966: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x2340119b vlan 0 vlan_tpid 0
02:04:13:572978: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:572989: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xe2f3 dscp CS0 ecn NON_ECN
    fragment id 0xffa4, flags DONT_FRAGMENT
  TCP: 34596 -> 6443
    seq. 0x81258b3a ack 0x5c066abe
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:572996: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8724 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34596 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:573004: error-drop
  rx:host-eth0
02:04:13:573005: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 931

02:04:13:572966: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c658 nsec 0x2342dd15 vlan 0 vlan_tpid 0
02:04:13:572978: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:572987: error-drop
  rx:host-eth0
02:04:13:572994: drop
  ethernet-input: l3 mac mismatch

Packet 932

02:04:13:572966: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x2342fd23 vlan 0 vlan_tpid 0
02:04:13:572978: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:572989: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xe2f2 dscp CS0 ecn NON_ECN
    fragment id 0xffa5, flags DONT_FRAGMENT
  TCP: 34596 -> 6443
    seq. 0x81258b3a ack 0x5c066ad8
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:572996: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8724 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34596 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:573004: error-drop
  rx:host-eth0
02:04:13:573005: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 933

02:04:13:572966: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c658 nsec 0x2344f39e vlan 0 vlan_tpid 0
02:04:13:572978: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:572987: error-drop
  rx:host-eth0
02:04:13:572994: drop
  ethernet-input: l3 mac mismatch

Packet 934

02:04:13:572966: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x234514ba vlan 0 vlan_tpid 0
02:04:13:572978: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:572989: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x83a8 dscp CS0 ecn NON_ECN
    fragment id 0x5ef0, flags DONT_FRAGMENT
  TCP: 34592 -> 6443
    seq. 0xfc6ee759 ack 0x769bc5cc
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:572996: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8720 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34592 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:573004: error-drop
  rx:host-eth0
02:04:13:573005: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 935

02:04:13:572966: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c658 nsec 0x23485f99 vlan 0 vlan_tpid 0
02:04:13:572978: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:572987: error-drop
  rx:host-eth0
02:04:13:572994: drop
  ethernet-input: l3 mac mismatch

Packet 936

02:04:13:572966: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x2348926f vlan 0 vlan_tpid 0
02:04:13:572978: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:572989: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xe2f1 dscp CS0 ecn NON_ECN
    fragment id 0xffa6, flags DONT_FRAGMENT
  TCP: 34596 -> 6443
    seq. 0x81258b3a ack 0x5c066af2
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:572996: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8724 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34596 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:573004: error-drop
  rx:host-eth0
02:04:13:573005: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 937

02:04:13:572966: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c658 nsec 0x234daa6f vlan 0 vlan_tpid 0
02:04:13:572978: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:572987: error-drop
  rx:host-eth0
02:04:13:572994: drop
  ethernet-input: l3 mac mismatch

Packet 938

02:04:13:572966: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x234dfacf vlan 0 vlan_tpid 0
02:04:13:572978: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:572989: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x83a7 dscp CS0 ecn NON_ECN
    fragment id 0x5ef1, flags DONT_FRAGMENT
  TCP: 34592 -> 6443
    seq. 0xfc6ee759 ack 0x769bc5e6
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:572996: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8720 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34592 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:573004: error-drop
  rx:host-eth0
02:04:13:573005: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 939

02:04:13:574115: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 96 snaplen 96 mac 66 net 80
      sec 0x5f35c658 nsec 0x2352a1cc vlan 0 vlan_tpid 0
02:04:13:574127: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:574133: error-drop
  rx:host-eth0
02:04:13:574138: drop
  ethernet-input: l3 mac mismatch

Packet 940

02:04:13:574115: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x2352cd1c vlan 0 vlan_tpid 0
02:04:13:574127: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:574135: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xe2f0 dscp CS0 ecn NON_ECN
    fragment id 0xffa7, flags DONT_FRAGMENT
  TCP: 34596 -> 6443
    seq. 0x81258b3a ack 0x5c066b10
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:574140: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8724 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34596 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:574146: error-drop
  rx:host-eth0
02:04:13:574147: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 941

02:04:13:574115: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c658 nsec 0x23564338 vlan 0 vlan_tpid 0
02:04:13:574127: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:574133: error-drop
  rx:host-eth0
02:04:13:574138: drop
  ethernet-input: l3 mac mismatch

Packet 942

02:04:13:574115: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x235663cf vlan 0 vlan_tpid 0
02:04:13:574127: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:574135: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x83a6 dscp CS0 ecn NON_ECN
    fragment id 0x5ef2, flags DONT_FRAGMENT
  TCP: 34592 -> 6443
    seq. 0xfc6ee759 ack 0x769bc600
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:574140: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8720 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34592 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:574146: error-drop
  rx:host-eth0
02:04:13:574147: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 943

02:04:13:574115: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 96 snaplen 96 mac 66 net 80
      sec 0x5f35c658 nsec 0x235a1a40 vlan 0 vlan_tpid 0
02:04:13:574127: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:574133: error-drop
  rx:host-eth0
02:04:13:574138: drop
  ethernet-input: l3 mac mismatch

Packet 944

02:04:13:574115: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x235a3a0f vlan 0 vlan_tpid 0
02:04:13:574127: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:574135: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x83a5 dscp CS0 ecn NON_ECN
    fragment id 0x5ef3, flags DONT_FRAGMENT
  TCP: 34592 -> 6443
    seq. 0xfc6ee759 ack 0x769bc61e
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:574140: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8720 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34592 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:574146: error-drop
  rx:host-eth0
02:04:13:574147: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 945

02:04:13:593481: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 96 snaplen 96 mac 66 net 80
      sec 0x5f35c658 nsec 0x247f1dcf vlan 0 vlan_tpid 0
02:04:13:593492: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:593500: error-drop
  rx:host-eth0
02:04:13:593506: drop
  ethernet-input: l3 mac mismatch

Packet 946

02:04:13:593481: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x247f652b vlan 0 vlan_tpid 0
02:04:13:593492: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:593502: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xe639 dscp CS0 ecn NON_ECN
    fragment id 0xfc5e, flags DONT_FRAGMENT
  TCP: 34588 -> 6443
    seq. 0xc95b57f0 ack 0x1659366d
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:593508: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b871c 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34588 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:593513: error-drop
  rx:host-eth0
02:04:13:593514: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 947

02:04:13:594588: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 130 snaplen 130 mac 66 net 80
      sec 0x5f35c658 nsec 0x2495d235 vlan 0 vlan_tpid 0
02:04:13:594819: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:594830: error-drop
  rx:host-eth0
02:04:13:594898: drop
  ethernet-input: l3 mac mismatch

Packet 948

02:04:13:594588: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x24962572 vlan 0 vlan_tpid 0
02:04:13:594819: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:594833: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xe638 dscp CS0 ecn NON_ECN
    fragment id 0xfc5f, flags DONT_FRAGMENT
  TCP: 34588 -> 6443
    seq. 0xc95b57f0 ack 0x165936ad
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:594900: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b871c 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34588 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:594917: error-drop
  rx:host-eth0
02:04:13:594918: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 949

02:04:13:594588: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 96 snaplen 96 mac 66 net 80
      sec 0x5f35c658 nsec 0x249677b6 vlan 0 vlan_tpid 0
02:04:13:594819: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:594830: error-drop
  rx:host-eth0
02:04:13:594898: drop
  ethernet-input: l3 mac mismatch

Packet 950

02:04:13:594588: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x2496937f vlan 0 vlan_tpid 0
02:04:13:594819: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:594833: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xe637 dscp CS0 ecn NON_ECN
    fragment id 0xfc60, flags DONT_FRAGMENT
  TCP: 34588 -> 6443
    seq. 0xc95b57f0 ack 0x165936cb
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:594900: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b871c 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34588 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:594917: error-drop
  rx:host-eth0
02:04:13:594918: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 951

02:04:13:594588: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 96 snaplen 96 mac 66 net 80
      sec 0x5f35c658 nsec 0x2496f031 vlan 0 vlan_tpid 0
02:04:13:594819: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:594830: error-drop
  rx:host-eth0
02:04:13:594898: drop
  ethernet-input: l3 mac mismatch

Packet 952

02:04:13:594588: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x24970875 vlan 0 vlan_tpid 0
02:04:13:594819: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:594833: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xe636 dscp CS0 ecn NON_ECN
    fragment id 0xfc61, flags DONT_FRAGMENT
  TCP: 34588 -> 6443
    seq. 0xc95b57f0 ack 0x165936e9
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:594900: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b871c 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34588 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:594917: error-drop
  rx:host-eth0
02:04:13:594918: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 953

02:04:13:594588: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c658 nsec 0x249735dc vlan 0 vlan_tpid 0
02:04:13:594819: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:594830: error-drop
  rx:host-eth0
02:04:13:594898: drop
  ethernet-input: l3 mac mismatch

Packet 954

02:04:13:594588: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x24975519 vlan 0 vlan_tpid 0
02:04:13:594819: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:594833: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xe635 dscp CS0 ecn NON_ECN
    fragment id 0xfc62, flags DONT_FRAGMENT
  TCP: 34588 -> 6443
    seq. 0xc95b57f0 ack 0x16593701
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:594900: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b871c 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34588 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:594917: error-drop
  rx:host-eth0
02:04:13:594918: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 955

02:04:13:594588: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c658 nsec 0x24976370 vlan 0 vlan_tpid 0
02:04:13:594819: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:594830: error-drop
  rx:host-eth0
02:04:13:594898: drop
  ethernet-input: l3 mac mismatch

Packet 956

02:04:13:594588: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x24979ab8 vlan 0 vlan_tpid 0
02:04:13:594819: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:594833: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xe634 dscp CS0 ecn NON_ECN
    fragment id 0xfc63, flags DONT_FRAGMENT
  TCP: 34588 -> 6443
    seq. 0xc95b57f0 ack 0x16593719
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:594900: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b871c 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34588 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:594917: error-drop
  rx:host-eth0
02:04:13:594918: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 957

02:04:13:595989: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 116 snaplen 116 mac 66 net 80
      sec 0x5f35c658 nsec 0x249a295d vlan 0 vlan_tpid 0
02:04:13:595999: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:596006: error-drop
  rx:host-eth0
02:04:13:596012: drop
  ethernet-input: l3 mac mismatch

Packet 958

02:04:13:595989: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x249a8f9d vlan 0 vlan_tpid 0
02:04:13:595999: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:596009: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xe633 dscp CS0 ecn NON_ECN
    fragment id 0xfc64, flags DONT_FRAGMENT
  TCP: 34588 -> 6443
    seq. 0xc95b57f0 ack 0x1659374b
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:596014: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b871c 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34588 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:596019: error-drop
  rx:host-eth0
02:04:13:596019: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 959

02:04:13:595989: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c658 nsec 0x249e3180 vlan 0 vlan_tpid 0
02:04:13:595999: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:596006: error-drop
  rx:host-eth0
02:04:13:596012: drop
  ethernet-input: l3 mac mismatch

Packet 960

02:04:13:595989: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x249e957e vlan 0 vlan_tpid 0
02:04:13:595999: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:596009: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xe632 dscp CS0 ecn NON_ECN
    fragment id 0xfc65, flags DONT_FRAGMENT
  TCP: 34588 -> 6443
    seq. 0xc95b57f0 ack 0x16593763
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:596014: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b871c 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34588 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:596019: error-drop
  rx:host-eth0
02:04:13:596019: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 961

02:04:13:595989: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x249ea8c6 vlan 0 vlan_tpid 0
02:04:13:595999: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:596006: error-drop
  rx:host-eth0
02:04:13:596012: drop
  ethernet-input: l3 mac mismatch

Packet 962

02:04:13:634674: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 274 snaplen 274 mac 66 net 80
      sec 0x5f35c658 nsec 0x26f688f9 vlan 0 vlan_tpid 0
02:04:13:634720: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:634726: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 260, checksum 0x82d4 dscp CS0 ecn NON_ECN
    fragment id 0x5ef4, flags DONT_FRAGMENT
  TCP: 34592 -> 6443
    seq. 0xfc6ee759 ack 0x769bc61e
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:634729: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8720 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34592 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:13:634734: error-drop
  rx:host-eth0
02:04:13:634735: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 963

02:04:13:635836: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c658 nsec 0x2707f7fa vlan 0 vlan_tpid 0
02:04:13:635847: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:635876: error-drop
  rx:host-eth0
02:04:13:635884: drop
  ethernet-input: l3 mac mismatch

Packet 964

02:04:13:635836: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x27085341 vlan 0 vlan_tpid 0
02:04:13:635847: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:635880: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x83a3 dscp CS0 ecn NON_ECN
    fragment id 0x5ef5, flags DONT_FRAGMENT
  TCP: 34592 -> 6443
    seq. 0xfc6ee829 ack 0x769bc636
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:635885: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8720 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34592 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:635891: error-drop
  rx:host-eth0
02:04:13:635891: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 965

02:04:13:635836: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 94 snaplen 94 mac 66 net 80
      sec 0x5f35c658 nsec 0x2709ae0d vlan 0 vlan_tpid 0
02:04:13:635847: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:635876: error-drop
  rx:host-eth0
02:04:13:635884: drop
  ethernet-input: l3 mac mismatch

Packet 966

02:04:13:635836: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 100 snaplen 100 mac 66 net 80
      sec 0x5f35c658 nsec 0x2709f35d vlan 0 vlan_tpid 0
02:04:13:635847: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:635876: error-drop
  rx:host-eth0
02:04:13:635884: drop
  ethernet-input: l3 mac mismatch

Packet 967

02:04:13:635836: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x270a553e vlan 0 vlan_tpid 0
02:04:13:635847: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:635880: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x83a2 dscp CS0 ecn NON_ECN
    fragment id 0x5ef6, flags DONT_FRAGMENT
  TCP: 34592 -> 6443
    seq. 0xfc6ee829 ack 0x769bc652
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:635885: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8720 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34592 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:635891: error-drop
  rx:host-eth0
02:04:13:635891: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 968

02:04:13:635836: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x270ad3ed vlan 0 vlan_tpid 0
02:04:13:635847: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:635880: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x83a1 dscp CS0 ecn NON_ECN
    fragment id 0x5ef7, flags DONT_FRAGMENT
  TCP: 34592 -> 6443
    seq. 0xfc6ee829 ack 0x769bc674
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:635885: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8720 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34592 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:635891: error-drop
  rx:host-eth0
02:04:13:635891: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 969

02:04:13:636976: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x271a943b vlan 0 vlan_tpid 0
02:04:13:636986: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:637327: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xe631 dscp CS0 ecn NON_ECN
    fragment id 0xfc66, flags DONT_FRAGMENT
  TCP: 34588 -> 6443
    seq. 0xc95b57f0 ack 0x16593764
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:637331: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b871c 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34588 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:637336: error-drop
  rx:host-eth0
02:04:13:637337: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 970

02:04:13:636976: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 274 snaplen 274 mac 66 net 80
      sec 0x5f35c658 nsec 0x271eee21 vlan 0 vlan_tpid 0
02:04:13:636986: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:637327: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 260, checksum 0xe21f dscp CS0 ecn NON_ECN
    fragment id 0xffa8, flags DONT_FRAGMENT
  TCP: 34596 -> 6443
    seq. 0x81258b3a ack 0x5c066b10
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:637331: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8724 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34596 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:13:637336: error-drop
  rx:host-eth0
02:04:13:637337: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 971

02:04:13:638794: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c658 nsec 0x27282333 vlan 0 vlan_tpid 0
02:04:13:638914: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:638924: error-drop
  rx:host-eth0
02:04:13:638931: drop
  ethernet-input: l3 mac mismatch

Packet 972

02:04:13:638794: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x27286348 vlan 0 vlan_tpid 0
02:04:13:638914: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:638926: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xe2ee dscp CS0 ecn NON_ECN
    fragment id 0xffa9, flags DONT_FRAGMENT
  TCP: 34596 -> 6443
    seq. 0x81258c0a ack 0x5c066b28
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:638933: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8724 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34596 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:639142: error-drop
  rx:host-eth0
02:04:13:639143: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 973

02:04:13:638794: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c658 nsec 0x272d053f vlan 0 vlan_tpid 0
02:04:13:638914: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:638924: error-drop
  rx:host-eth0
02:04:13:638931: drop
  ethernet-input: l3 mac mismatch

Packet 974

02:04:13:638794: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x272d7ab7 vlan 0 vlan_tpid 0
02:04:13:638914: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:638926: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xe2ed dscp CS0 ecn NON_ECN
    fragment id 0xffaa, flags DONT_FRAGMENT
  TCP: 34596 -> 6443
    seq. 0x81258c0a ack 0x5c066b40
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:638933: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8724 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34596 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:639142: error-drop
  rx:host-eth0
02:04:13:639143: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 975

02:04:13:638794: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c658 nsec 0x27313dc1 vlan 0 vlan_tpid 0
02:04:13:638914: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:638924: error-drop
  rx:host-eth0
02:04:13:638931: drop
  ethernet-input: l3 mac mismatch

Packet 976

02:04:13:638794: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x2731b581 vlan 0 vlan_tpid 0
02:04:13:638914: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:638926: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xe2ec dscp CS0 ecn NON_ECN
    fragment id 0xffab, flags DONT_FRAGMENT
  TCP: 34596 -> 6443
    seq. 0x81258c0a ack 0x5c066b5a
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:638933: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8724 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34596 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:639142: error-drop
  rx:host-eth0
02:04:13:639143: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 977

02:04:13:638794: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c658 nsec 0x27344b15 vlan 0 vlan_tpid 0
02:04:13:638914: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:638924: error-drop
  rx:host-eth0
02:04:13:638931: drop
  ethernet-input: l3 mac mismatch

Packet 978

02:04:13:638794: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x2734c551 vlan 0 vlan_tpid 0
02:04:13:638914: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:638926: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xe2eb dscp CS0 ecn NON_ECN
    fragment id 0xffac, flags DONT_FRAGMENT
  TCP: 34596 -> 6443
    seq. 0x81258c0a ack 0x5c066b74
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:638933: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8724 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34596 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:639142: error-drop
  rx:host-eth0
02:04:13:639143: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 979

02:04:13:638794: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 96 snaplen 96 mac 66 net 80
      sec 0x5f35c658 nsec 0x2736c471 vlan 0 vlan_tpid 0
02:04:13:638914: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:638924: error-drop
  rx:host-eth0
02:04:13:638931: drop
  ethernet-input: l3 mac mismatch

Packet 980

02:04:13:638794: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x27374cab vlan 0 vlan_tpid 0
02:04:13:638914: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:638926: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xe2ea dscp CS0 ecn NON_ECN
    fragment id 0xffad, flags DONT_FRAGMENT
  TCP: 34596 -> 6443
    seq. 0x81258c0a ack 0x5c066b92
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:638933: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8724 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34596 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:639142: error-drop
  rx:host-eth0
02:04:13:639143: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 981

02:04:13:653957: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 90 snaplen 90 mac 66 net 80
      sec 0x5f35c658 nsec 0x281d63b3 vlan 0 vlan_tpid 0
02:04:13:653967: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:653973: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 76, checksum 0xe618 dscp CS0 ecn NON_ECN
    fragment id 0xfc67, flags DONT_FRAGMENT
  TCP: 34588 -> 6443
    seq. 0xc95b57f0 ack 0x16593764
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:653979: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b871c 0318ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34588 -> 6443 tcp flags (valid) 18 rsvd 0
02:04:13:653986: error-drop
  rx:host-eth0
02:04:13:653986: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 982

02:04:13:653957: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000001 len 54 snaplen 54 mac 66 net 80
      sec 0x5f35c658 nsec 0x281dbed7 vlan 0 vlan_tpid 0
02:04:13:653967: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:653977: error-drop
  rx:host-eth0
02:04:13:653984: drop
  ethernet-input: l3 mac mismatch

Packet 983

02:04:13:664230: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 74 snaplen 74 mac 66 net 80
      sec 0x5f35c658 nsec 0x28b88640 vlan 0 vlan_tpid 0
02:04:13:664242: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:664256: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 60, checksum 0x0ada dscp CS0 ecn NON_ECN
    fragment id 0xd7b6, flags DONT_FRAGMENT
  TCP: 34620 -> 6443
    seq. 0xba225a37 ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 64240, checksum 0x0000
02:04:13:664262: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b873c 0302ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34620 -> 6443 tcp flags (valid) 02 rsvd 0
02:04:13:664269: error-drop
  rx:host-eth0
02:04:13:664269: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 984

02:04:13:664230: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 74 snaplen 74 mac 66 net 80
      sec 0x5f35c658 nsec 0x28b904e9 vlan 0 vlan_tpid 0
02:04:13:664242: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:664260: error-drop
  rx:host-eth0
02:04:13:664267: drop
  ethernet-input: l3 mac mismatch

Packet 985

02:04:13:664230: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x28b9440d vlan 0 vlan_tpid 0
02:04:13:664242: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:664256: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x0ae1 dscp CS0 ecn NON_ECN
    fragment id 0xd7b7, flags DONT_FRAGMENT
  TCP: 34620 -> 6443
    seq. 0xba225a38 ack 0x4e3ba14c
    flags 0x10 ACK, tcp header: 32 bytes
    window 502, checksum 0x0000
02:04:13:664262: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b873c 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34620 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:664269: error-drop
  rx:host-eth0
02:04:13:664269: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 986

02:04:13:686067: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 96 snaplen 96 mac 66 net 80
      sec 0x5f35c658 nsec 0x29ff67c4 vlan 0 vlan_tpid 0
02:04:13:686075: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:686082: error-drop
  rx:host-eth0
02:04:13:686089: drop
  ethernet-input: l3 mac mismatch

Packet 987

02:04:13:686067: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x2a003e55 vlan 0 vlan_tpid 0
02:04:13:686075: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:686086: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x83a0 dscp CS0 ecn NON_ECN
    fragment id 0x5ef8, flags DONT_FRAGMENT
  TCP: 34592 -> 6443
    seq. 0xfc6ee829 ack 0x769bc692
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:686091: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8720 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34592 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:686096: error-drop
  rx:host-eth0
02:04:13:686097: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 988

02:04:13:688326: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c658 nsec 0x2a2aee88 vlan 0 vlan_tpid 0
02:04:13:688333: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:688339: error-drop
  rx:host-eth0
02:04:13:688392: drop
  ethernet-input: l3 mac mismatch

Packet 989

02:04:13:688326: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x2a2bb8ff vlan 0 vlan_tpid 0
02:04:13:688333: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:688342: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xe2e9 dscp CS0 ecn NON_ECN
    fragment id 0xffae, flags DONT_FRAGMENT
  TCP: 34596 -> 6443
    seq. 0x81258c0a ack 0x5c066bac
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:688394: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8724 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34596 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:688399: error-drop
  rx:host-eth0
02:04:13:688400: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 990

02:04:13:688326: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 92 snaplen 92 mac 66 net 80
      sec 0x5f35c658 nsec 0x2a2be6e3 vlan 0 vlan_tpid 0
02:04:13:688333: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:688339: error-drop
  rx:host-eth0
02:04:13:688392: drop
  ethernet-input: l3 mac mismatch

Packet 991

02:04:13:688326: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x2a2c3762 vlan 0 vlan_tpid 0
02:04:13:688333: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:688342: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xe2e8 dscp CS0 ecn NON_ECN
    fragment id 0xffaf, flags DONT_FRAGMENT
  TCP: 34596 -> 6443
    seq. 0x81258c0a ack 0x5c066bc6
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:688394: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8724 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34596 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:688399: error-drop
  rx:host-eth0
02:04:13:688400: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 992

02:04:13:690590: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 130 snaplen 130 mac 66 net 80
      sec 0x5f35c658 nsec 0x2a4f7ef6 vlan 0 vlan_tpid 0
02:04:13:690601: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:690609: error-drop
  rx:host-eth0
02:04:13:690685: drop
  ethernet-input: l3 mac mismatch

Packet 993

02:04:13:690590: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x2a505332 vlan 0 vlan_tpid 0
02:04:13:690601: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:690681: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x839f dscp CS0 ecn NON_ECN
    fragment id 0x5ef9, flags DONT_FRAGMENT
  TCP: 34592 -> 6443
    seq. 0xfc6ee829 ack 0x769bc6d2
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:690688: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8720 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34592 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:690693: error-drop
  rx:host-eth0
02:04:13:690694: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 994

02:04:13:690590: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 100 snaplen 100 mac 66 net 80
      sec 0x5f35c658 nsec 0x2a50aa7a vlan 0 vlan_tpid 0
02:04:13:690601: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:690609: error-drop
  rx:host-eth0
02:04:13:690685: drop
  ethernet-input: l3 mac mismatch

Packet 995

02:04:13:690590: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x2a51016f vlan 0 vlan_tpid 0
02:04:13:690601: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:690681: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0x839e dscp CS0 ecn NON_ECN
    fragment id 0x5efa, flags DONT_FRAGMENT
  TCP: 34592 -> 6443
    seq. 0xfc6ee829 ack 0x769bc6f4
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:690688: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8720 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34592 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:690693: error-drop
  rx:host-eth0
02:04:13:690694: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 996

02:04:13:691849: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 96 snaplen 96 mac 66 net 80
      sec 0x5f35c658 nsec 0x2a594bb7 vlan 0 vlan_tpid 0
02:04:13:691864: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:691872: error-drop
  rx:host-eth0
02:04:13:692140: drop
  ethernet-input: l3 mac mismatch

Packet 997

02:04:13:691849: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x2a59f9a4 vlan 0 vlan_tpid 0
02:04:13:691864: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:691875: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xe2e7 dscp CS0 ecn NON_ECN
    fragment id 0xffb0, flags DONT_FRAGMENT
  TCP: 34596 -> 6443
    seq. 0x81258c0a ack 0x5c066be4
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:692143: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8724 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34596 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:692149: error-drop
  rx:host-eth0
02:04:13:692150: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 998

02:04:13:691849: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 134 snaplen 134 mac 66 net 80
      sec 0x5f35c658 nsec 0x2a5c393b vlan 0 vlan_tpid 0
02:04:13:691864: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:691872: error-drop
  rx:host-eth0
02:04:13:692140: drop
  ethernet-input: l3 mac mismatch

Packet 999

02:04:13:691849: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 94 snaplen 94 mac 66 net 80
      sec 0x5f35c658 nsec 0x2a5c7e44 vlan 0 vlan_tpid 0
02:04:13:691864: ethernet-input
  IP4: 02:42:ac:13:00:04 -> 02:42:3e:dc:b2:b5
02:04:13:691872: error-drop
  rx:host-eth0
02:04:13:692140: drop
  ethernet-input: l3 mac mismatch

Packet 1000

02:04:13:691849: af-packet-input
  af_packet: hw_if_index 1 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 66 net 80
      sec 0x5f35c658 nsec 0x2a5c9e13 vlan 0 vlan_tpid 0
02:04:13:691864: ethernet-input
  IP4: 02:42:3e:dc:b2:b5 -> 02:42:ac:13:00:04
02:04:13:691875: ip4-input
  TCP: 172.19.0.1 -> 172.19.0.4
    tos 0x00, ttl 64, length 52, checksum 0xe2e6 dscp CS0 ecn NON_ECN
    fragment id 0xffb1, flags DONT_FRAGMENT
  TCP: 34596 -> 6443
    seq. 0x81258c0a ack 0x5c066c28
    flags 0x10 ACK, tcp header: 32 bytes
    window 501, checksum 0x0000
02:04:13:692143: acl-plugin-in-ip4-fa
  acl-plugin: lc_index: 0, sw_if_index 1, next index 0, action: 0, match: acl -1 rule -1 trace_bits 00000000
  pkt info 0000000000000000 0000000000000000 0000000000000000 040013ac010013ac 00010106192b8724 0310ffff00000000
   lc_index 0 l3 ip4 172.19.0.1 -> 172.19.0.4 l4 lsb_of_sw_if_index 1 proto 6 l4_is_input 1 l4_slow_path 0 l4_flags 0x01 port 34596 -> 6443 tcp flags (valid) 10 rsvd 0
02:04:13:692149: error-drop
  rx:host-eth0
02:04:13:692150: drop
  acl-plugin-in-ip4-fa: ACL deny packets

Packet 1001

02:04:16:160491: memif-input
  memif: hw_if_index 6 next-index 4
    slot: ring 0
02:04:16:160496: ethernet-input
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
02:04:16:160499: l2-input
  l2-input: sw_if_index 6 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4
02:04:16:160500: l2-output
  l2-output: sw_if_index 7 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4 data 08 00 45 00 00 3c a7 05 40 00 3e 06
02:04:16:160501: tap0-output
  tap0 
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
  TCP: 172.55.252.1 -> 172.55.244.5
    tos 0x00, ttl 62, length 60, checksum 0x4d40 dscp CS0 ecn NON_ECN
    fragment id 0xa705, flags DONT_FRAGMENT
  TCP: 40118 -> 5000
    seq. 0x218c987e ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 64860, checksum 0x202b

Packet 1002

02:04:16:161549: virtio-input
  virtio: hw_if_index 7 next-index 4 vring 0 len 42
    hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
02:04:16:161555: ethernet-input
  ARP: 02:fe:e3:96:41:29 -> ff:ff:ff:ff:ff:ff
02:04:16:161556: l2-input
  l2-input: sw_if_index 7 dst ff:ff:ff:ff:ff:ff src 02:fe:e3:96:41:29
02:04:16:161558: l2-output
  l2-output: sw_if_index 6 dst ff:ff:ff:ff:ff:ff src 02:fe:e3:96:41:29 data 08 06 00 01 08 00 06 04 00 01 02 fe
02:04:16:161559: memif3/0-output
  memif3/0 
  ARP: 02:fe:e3:96:41:29 -> ff:ff:ff:ff:ff:ff
  request, type ethernet/IP4, address size 6/4
  02:fe:e3:96:41:29/172.55.244.5 -> 00:00:00:00:00:00/172.55.244.6

Packet 1003

02:04:16:162661: memif-input
  memif: hw_if_index 6 next-index 4
    slot: ring 0
02:04:16:162664: ethernet-input
  ARP: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
02:04:16:162665: l2-input
  l2-input: sw_if_index 6 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4
02:04:16:162666: l2-output
  l2-output: sw_if_index 7 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4 data 08 06 00 01 08 00 06 04 00 02 02 fe
02:04:16:162667: tap0-output
  tap0 
  ARP: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
  reply, type ethernet/IP4, address size 6/4
  02:fe:09:5a:c0:e4/172.55.244.6 -> 02:fe:e3:96:41:29/172.55.244.5

Packet 1004

02:04:16:163726: virtio-input
  virtio: hw_if_index 7 next-index 4 vring 0 len 74
    hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
02:04:16:163732: ethernet-input
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
02:04:16:163734: l2-input
  l2-input: sw_if_index 7 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29
02:04:16:163736: l2-output
  l2-output: sw_if_index 6 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29 data 08 00 45 00 00 3c 00 00 40 00 40 06
02:04:16:163737: memif3/0-output
  memif3/0 
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
  TCP: 172.55.244.5 -> 172.55.252.1
    tos 0x00, ttl 64, length 60, checksum 0xf245 dscp CS0 ecn NON_ECN
    fragment id 0x0000, flags DONT_FRAGMENT
  TCP: 5000 -> 40118
    seq. 0x483b86b1 ack 0x218c987f
    flags 0x12 SYN ACK, tcp header: 40 bytes
    window 64308, checksum 0xaf14

Packet 1005

02:04:16:166080: memif-input
  memif: hw_if_index 2 next-index 4
    slot: ring 0
02:04:16:166113: ethernet-input
  IP4: 02:fe:7c:39:0d:4a -> 02:fe:af:46:8f:24
02:04:16:166117: l2-input
  l2-input: sw_if_index 2 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a
02:04:16:166119: l2-output
  l2-output: sw_if_index 3 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a data 08 00 45 00 00 3c 00 00 40 00 3f 06
02:04:16:166121: vxlan4-encap
  VXLAN encap to vxlan_tunnel0 vni 2
02:04:16:166125: ip4-rewrite
  tx_sw_if_index 1 dpo-idx 15 : ipv4 via 172.19.0.3 host-eth0: mtu:9000 0242ac1300030242ac1300040800 flow hash: 0xb7290a2f
  00000000: 0242ac1300030242ac13000408004500006e00000000fd116551ac130004ac13
  00000020: 00032f0a12b5005a0000080000000000020002feaf468f2402fe7c39
02:04:16:166128: host-eth0-output
  host-eth0 
  IP4: 02:42:ac:13:00:04 -> 02:42:ac:13:00:03
  UDP: 172.19.0.4 -> 172.19.0.3
    tos 0x00, ttl 253, length 110, checksum 0x6551 dscp CS0 ecn NON_ECN
    fragment id 0x0000
  UDP: 12042 -> 4789
    length 90, checksum 0x0000

Packet 1006

02:04:16:172991: memif-input
  memif: hw_if_index 6 next-index 4
    slot: ring 0
02:04:16:172996: ethernet-input
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
02:04:16:172999: l2-input
  l2-input: sw_if_index 6 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4
02:04:16:173000: l2-output
  l2-output: sw_if_index 7 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4 data 08 00 45 00 00 34 a7 06 40 00 3e 06
02:04:16:173001: tap0-output
  tap0 
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
  TCP: 172.55.252.1 -> 172.55.244.5
    tos 0x00, ttl 62, length 52, checksum 0x4d47 dscp CS0 ecn NON_ECN
    fragment id 0xa706, flags DONT_FRAGMENT
  TCP: 40118 -> 5000
    seq. 0x218c987f ack 0x483b86b2
    flags 0x10 ACK, tcp header: 32 bytes
    window 507, checksum 0xd6d8

Packet 1007

02:04:16:172991: memif-input
  memif: hw_if_index 6 next-index 4
    slot: ring 0
02:04:16:172996: ethernet-input
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
02:04:16:172999: l2-input
  l2-input: sw_if_index 6 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4
02:04:16:173000: l2-output
  l2-output: sw_if_index 7 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4 data 08 00 45 00 00 8a a7 07 40 00 3e 06
02:04:16:173001: tap0-output
  tap0 
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
  TCP: 172.55.252.1 -> 172.55.244.5
    tos 0x00, ttl 62, length 138, checksum 0x4cf0 dscp CS0 ecn NON_ECN
    fragment id 0xa707, flags DONT_FRAGMENT
  TCP: 40118 -> 5000
    seq. 0x218c987f ack 0x483b86b2
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 507, checksum 0xf5c7

Packet 1008

02:04:16:174047: virtio-input
  virtio: hw_if_index 7 next-index 4 vring 0 len 66
    hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
02:04:16:174056: ethernet-input
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
02:04:16:174061: l2-input
  l2-input: sw_if_index 7 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29
02:04:16:174064: l2-output
  l2-output: sw_if_index 6 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29 data 08 00 45 00 00 34 39 6e 40 00 40 06
02:04:16:174066: memif3/0-output
  memif3/0 
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
  TCP: 172.55.244.5 -> 172.55.252.1
    tos 0x00, ttl 64, length 52, checksum 0xb8df dscp CS0 ecn NON_ECN
    fragment id 0x396e, flags DONT_FRAGMENT
  TCP: 5000 -> 40118
    seq. 0x483b86b2 ack 0x218c98d5
    flags 0x10 ACK, tcp header: 32 bytes
    window 502, checksum 0xd67a

Packet 1009

02:04:16:187713: memif-input
  memif: hw_if_index 2 next-index 4
    slot: ring 0
02:04:16:187722: ethernet-input
  IP4: 02:fe:7c:39:0d:4a -> 02:fe:af:46:8f:24
02:04:16:187728: l2-input
  l2-input: sw_if_index 2 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a
02:04:16:187731: l2-output
  l2-output: sw_if_index 3 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a data 08 00 45 00 00 34 39 6e 40 00 3f 06
02:04:16:187733: vxlan4-encap
  VXLAN encap to vxlan_tunnel0 vni 2
02:04:16:187736: ip4-rewrite
  tx_sw_if_index 1 dpo-idx 15 : ipv4 via 172.19.0.3 host-eth0: mtu:9000 0242ac1300030242ac1300040800 flow hash: 0xb7290a2f
  00000000: 0242ac1300030242ac13000408004500006600000000fd116559ac130004ac13
  00000020: 00032f0a12b500520000080000000000020002feaf468f2402fe7c39
02:04:16:187739: host-eth0-output
  host-eth0 
  IP4: 02:42:ac:13:00:04 -> 02:42:ac:13:00:03
  UDP: 172.19.0.4 -> 172.19.0.3
    tos 0x00, ttl 253, length 102, checksum 0x6559 dscp CS0 ecn NON_ECN
    fragment id 0x0000
  UDP: 12042 -> 4789
    length 82, checksum 0x0000

Packet 1010

02:04:16:315942: virtio-input
  virtio: hw_if_index 7 next-index 4 vring 0 len 83
    hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
02:04:16:315949: ethernet-input
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
02:04:16:315953: l2-input
  l2-input: sw_if_index 7 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29
02:04:16:315955: l2-output
  l2-output: sw_if_index 6 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29 data 08 00 45 00 00 45 39 6f 40 00 40 06
02:04:16:315956: memif3/0-output
  memif3/0 
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
  TCP: 172.55.244.5 -> 172.55.252.1
    tos 0x00, ttl 64, length 69, checksum 0xb8cd dscp CS0 ecn NON_ECN
    fragment id 0x396f, flags DONT_FRAGMENT
  TCP: 5000 -> 40118
    seq. 0x483b86b2 ack 0x218c98d5
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 502, checksum 0x160f

Packet 1011

02:04:16:315942: virtio-input
  virtio: hw_if_index 7 next-index 4 vring 0 len 265
    hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
02:04:16:315949: ethernet-input
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
02:04:16:315953: l2-input
  l2-input: sw_if_index 7 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29
02:04:16:315955: l2-output
  l2-output: sw_if_index 6 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29 data 08 00 45 00 00 fb 39 70 40 00 40 06
02:04:16:315956: memif3/0-output
  memif3/0 
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
  TCP: 172.55.244.5 -> 172.55.252.1
    tos 0x00, ttl 64, length 251, checksum 0xb816 dscp CS0 ecn NON_ECN
    fragment id 0x3970, flags DONT_FRAGMENT
  TCP: 5000 -> 40118
    seq. 0x483b86c3 ack 0x218c98d5
    flags 0x19 FIN PSH ACK, tcp header: 32 bytes
    window 502, checksum 0xd201

Packet 1012

02:04:16:317025: memif-input
  memif: hw_if_index 2 next-index 4
    slot: ring 0
02:04:16:317030: ethernet-input
  IP4: 02:fe:7c:39:0d:4a -> 02:fe:af:46:8f:24
02:04:16:317032: l2-input
  l2-input: sw_if_index 2 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a
02:04:16:317033: l2-output
  l2-output: sw_if_index 3 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a data 08 00 45 00 00 45 39 6f 40 00 3f 06
02:04:16:317033: vxlan4-encap
  VXLAN encap to vxlan_tunnel0 vni 2
02:04:16:317036: ip4-rewrite
  tx_sw_if_index 1 dpo-idx 15 : ipv4 via 172.19.0.3 host-eth0: mtu:9000 0242ac1300030242ac1300040800 flow hash: 0xb7290a2f
  00000000: 0242ac1300030242ac13000408004500007700000000fd116548ac130004ac13
  00000020: 00032f0a12b500630000080000000000020002feaf468f2402fe7c39
02:04:16:317037: host-eth0-output
  host-eth0 
  IP4: 02:42:ac:13:00:04 -> 02:42:ac:13:00:03
  UDP: 172.19.0.4 -> 172.19.0.3
    tos 0x00, ttl 253, length 119, checksum 0x6548 dscp CS0 ecn NON_ECN
    fragment id 0x0000
  UDP: 12042 -> 4789
    length 99, checksum 0x0000

Packet 1013

02:04:16:317025: memif-input
  memif: hw_if_index 2 next-index 4
    slot: ring 0
02:04:16:317030: ethernet-input
  IP4: 02:fe:7c:39:0d:4a -> 02:fe:af:46:8f:24
02:04:16:317032: l2-input
  l2-input: sw_if_index 2 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a
02:04:16:317033: l2-output
  l2-output: sw_if_index 3 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a data 08 00 45 00 00 fb 39 70 40 00 3f 06
02:04:16:317033: vxlan4-encap
  VXLAN encap to vxlan_tunnel0 vni 2
02:04:16:317036: ip4-rewrite
  tx_sw_if_index 1 dpo-idx 15 : ipv4 via 172.19.0.3 host-eth0: mtu:9000 0242ac1300030242ac1300040800 flow hash: 0xb7290a2f
  00000000: 0242ac1300030242ac13000408004500012d00000000fd116492ac130004ac13
  00000020: 00032f0a12b501190000080000000000020002feaf468f2402fe7c39
02:04:16:317037: host-eth0-output
  host-eth0 
  IP4: 02:42:ac:13:00:04 -> 02:42:ac:13:00:03
  UDP: 172.19.0.4 -> 172.19.0.3
    tos 0x00, ttl 253, length 301, checksum 0x6492 dscp CS0 ecn NON_ECN
    fragment id 0x0000
  UDP: 12042 -> 4789
    length 281, checksum 0x0000

Packet 1014

02:04:16:324159: memif-input
  memif: hw_if_index 6 next-index 4
    slot: ring 0
02:04:16:324167: ethernet-input
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
02:04:16:324171: l2-input
  l2-input: sw_if_index 6 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4
02:04:16:324174: l2-output
  l2-output: sw_if_index 7 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4 data 08 00 45 00 00 34 a7 08 40 00 3e 06
02:04:16:324176: tap0-output
  tap0 
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
  TCP: 172.55.252.1 -> 172.55.244.5
    tos 0x00, ttl 62, length 52, checksum 0x4d45 dscp CS0 ecn NON_ECN
    fragment id 0xa708, flags DONT_FRAGMENT
  TCP: 40118 -> 5000
    seq. 0x218c98d5 ack 0x483b86c3
    flags 0x10 ACK, tcp header: 32 bytes
    window 507, checksum 0xd540

Packet 1015

02:04:16:324159: memif-input
  memif: hw_if_index 6 next-index 4
    slot: ring 0
02:04:16:324167: ethernet-input
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
02:04:16:324171: l2-input
  l2-input: sw_if_index 6 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4
02:04:16:324174: l2-output
  l2-output: sw_if_index 7 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4 data 08 00 45 00 00 34 a7 09 40 00 3e 06
02:04:16:324176: tap0-output
  tap0 
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
  TCP: 172.55.252.1 -> 172.55.244.5
    tos 0x00, ttl 62, length 52, checksum 0x4d44 dscp CS0 ecn NON_ECN
    fragment id 0xa709, flags DONT_FRAGMENT
  TCP: 40118 -> 5000
    seq. 0x218c98d5 ack 0x483b878b
    flags 0x11 FIN ACK, tcp header: 32 bytes
    window 506, checksum 0xd478

Packet 1016

02:04:16:325256: virtio-input
  virtio: hw_if_index 7 next-index 4 vring 0 len 66
    hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
02:04:16:325264: ethernet-input
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
02:04:16:325269: l2-input
  l2-input: sw_if_index 7 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29
02:04:16:325271: l2-output
  l2-output: sw_if_index 6 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29 data 08 00 45 00 00 34 39 71 40 00 40 06
02:04:16:325273: memif3/0-output
  memif3/0 
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
  TCP: 172.55.244.5 -> 172.55.252.1
    tos 0x00, ttl 64, length 52, checksum 0xb8dc dscp CS0 ecn NON_ECN
    fragment id 0x3971, flags DONT_FRAGMENT
  TCP: 5000 -> 40118
    seq. 0x483b878b ack 0x218c98d6
    flags 0x10 ACK, tcp header: 32 bytes
    window 502, checksum 0xd473

Packet 1017

02:04:16:329091: memif-input
  memif: hw_if_index 2 next-index 4
    slot: ring 0
02:04:16:329097: ethernet-input
  IP4: 02:fe:7c:39:0d:4a -> 02:fe:af:46:8f:24
02:04:16:329101: l2-input
  l2-input: sw_if_index 2 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a
02:04:16:329102: l2-output
  l2-output: sw_if_index 3 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a data 08 00 45 00 00 34 39 71 40 00 3f 06
02:04:16:329104: vxlan4-encap
  VXLAN encap to vxlan_tunnel0 vni 2
02:04:16:329108: ip4-rewrite
  tx_sw_if_index 1 dpo-idx 15 : ipv4 via 172.19.0.3 host-eth0: mtu:9000 0242ac1300030242ac1300040800 flow hash: 0xb7290a2f
  00000000: 0242ac1300030242ac13000408004500006600000000fd116559ac130004ac13
  00000020: 00032f0a12b500520000080000000000020002feaf468f2402fe7c39
02:04:16:329110: host-eth0-output
  host-eth0 
  IP4: 02:42:ac:13:00:04 -> 02:42:ac:13:00:03
  UDP: 172.19.0.4 -> 172.19.0.3
    tos 0x00, ttl 253, length 102, checksum 0x6559 dscp CS0 ecn NON_ECN
    fragment id 0x0000
  UDP: 12042 -> 4789
    length 82, checksum 0x0000

Packet 1018

02:04:16:543406: memif-input
  memif: hw_if_index 6 next-index 4
    slot: ring 0
02:04:16:543414: ethernet-input
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
02:04:16:543419: l2-input
  l2-input: sw_if_index 6 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4
02:04:16:543421: l2-output
  l2-output: sw_if_index 7 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4 data 08 00 45 00 00 3c 28 2f 40 00 3e 06
02:04:16:543423: tap0-output
  tap0 
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
  TCP: 172.55.252.1 -> 172.55.244.5
    tos 0x00, ttl 62, length 60, checksum 0xcc16 dscp CS0 ecn NON_ECN
    fragment id 0x282f, flags DONT_FRAGMENT
  TCP: 40146 -> 5000
    seq. 0xfc10a628 ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 64860, checksum 0x366b

Packet 1019

02:04:16:550867: virtio-input
  virtio: hw_if_index 7 next-index 4 vring 0 len 74
    hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
02:04:16:550872: ethernet-input
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
02:04:16:550881: l2-input
  l2-input: sw_if_index 7 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29
02:04:16:550888: l2-output
  l2-output: sw_if_index 6 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29 data 08 00 45 00 00 3c 00 00 40 00 40 06
02:04:16:550891: memif3/0-output
  memif3/0 
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
  TCP: 172.55.244.5 -> 172.55.252.1
    tos 0x00, ttl 64, length 60, checksum 0xf245 dscp CS0 ecn NON_ECN
    fragment id 0x0000, flags DONT_FRAGMENT
  TCP: 5000 -> 40146
    seq. 0x620777c4 ack 0xfc10a629
    flags 0x12 SYN ACK, tcp header: 40 bytes
    window 64308, checksum 0xb8f6

Packet 1020

02:04:16:551994: memif-input
  memif: hw_if_index 2 next-index 4
    slot: ring 0
02:04:16:551999: ethernet-input
  IP4: 02:fe:7c:39:0d:4a -> 02:fe:af:46:8f:24
02:04:16:552001: l2-input
  l2-input: sw_if_index 2 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a
02:04:16:552002: l2-output
  l2-output: sw_if_index 3 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a data 08 00 45 00 00 3c 00 00 40 00 3f 06
02:04:16:552002: vxlan4-encap
  VXLAN encap to vxlan_tunnel0 vni 2
02:04:16:552004: ip4-rewrite
  tx_sw_if_index 1 dpo-idx 15 : ipv4 via 172.19.0.3 host-eth0: mtu:9000 0242ac1300030242ac1300040800 flow hash: 0x13484003
  00000000: 0242ac1300030242ac13000408004500006e00000000fd116551ac130004ac13
  00000020: 0003034012b5005a0000080000000000020002feaf468f2402fe7c39
02:04:16:552006: host-eth0-output
  host-eth0 
  IP4: 02:42:ac:13:00:04 -> 02:42:ac:13:00:03
  UDP: 172.19.0.4 -> 172.19.0.3
    tos 0x00, ttl 253, length 110, checksum 0x6551 dscp CS0 ecn NON_ECN
    fragment id 0x0000
  UDP: 832 -> 4789
    length 90, checksum 0x0000

Packet 1021

02:04:16:556527: memif-input
  memif: hw_if_index 6 next-index 4
    slot: ring 0
02:04:16:556532: ethernet-input
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
02:04:16:556534: l2-input
  l2-input: sw_if_index 6 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4
02:04:16:556536: l2-output
  l2-output: sw_if_index 7 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4 data 08 00 45 00 00 34 28 30 40 00 3e 06
02:04:16:556538: tap0-output
  tap0 
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
  TCP: 172.55.252.1 -> 172.55.244.5
    tos 0x00, ttl 62, length 52, checksum 0xcc1d dscp CS0 ecn NON_ECN
    fragment id 0x2830, flags DONT_FRAGMENT
  TCP: 40146 -> 5000
    seq. 0xfc10a629 ack 0x620777c5
    flags 0x10 ACK, tcp header: 32 bytes
    window 507, checksum 0xe0af

Packet 1022

02:04:16:557597: memif-input
  memif: hw_if_index 6 next-index 4
    slot: ring 0
02:04:16:557599: ethernet-input
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
02:04:16:557601: l2-input
  l2-input: sw_if_index 6 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4
02:04:16:557601: l2-output
  l2-output: sw_if_index 7 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4 data 08 00 45 00 00 a0 28 31 40 00 3e 06
02:04:16:557602: tap0-output
  tap0 
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
  TCP: 172.55.252.1 -> 172.55.244.5
    tos 0x00, ttl 62, length 160, checksum 0xcbb0 dscp CS0 ecn NON_ECN
    fragment id 0x2831, flags DONT_FRAGMENT
  TCP: 40146 -> 5000
    seq. 0xfc10a629 ack 0x620777c5
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 507, checksum 0x3db3

Packet 1023

02:04:16:567655: virtio-input
  virtio: hw_if_index 7 next-index 4 vring 0 len 66
    hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
02:04:16:567661: ethernet-input
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
02:04:16:567674: l2-input
  l2-input: sw_if_index 7 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29
02:04:16:567684: l2-output
  l2-output: sw_if_index 6 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29 data 08 00 45 00 00 34 f6 90 40 00 40 06
02:04:16:567687: memif3/0-output
  memif3/0 
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
  TCP: 172.55.244.5 -> 172.55.252.1
    tos 0x00, ttl 64, length 52, checksum 0xfbbc dscp CS0 ecn NON_ECN
    fragment id 0xf690, flags DONT_FRAGMENT
  TCP: 5000 -> 40146
    seq. 0x620777c5 ack 0xfc10a695
    flags 0x10 ACK, tcp header: 32 bytes
    window 502, checksum 0xe03a

Packet 1024

02:04:16:569892: memif-input
  memif: hw_if_index 2 next-index 4
    slot: ring 0
02:04:16:569901: ethernet-input
  IP4: 02:fe:7c:39:0d:4a -> 02:fe:af:46:8f:24
02:04:16:569905: l2-input
  l2-input: sw_if_index 2 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a
02:04:16:569906: l2-output
  l2-output: sw_if_index 3 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a data 08 00 45 00 00 34 f6 90 40 00 3f 06
02:04:16:569908: vxlan4-encap
  VXLAN encap to vxlan_tunnel0 vni 2
02:04:16:569910: ip4-rewrite
  tx_sw_if_index 1 dpo-idx 15 : ipv4 via 172.19.0.3 host-eth0: mtu:9000 0242ac1300030242ac1300040800 flow hash: 0x13484003
  00000000: 0242ac1300030242ac13000408004500006600000000fd116559ac130004ac13
  00000020: 0003034012b500520000080000000000020002feaf468f2402fe7c39
02:04:16:569912: host-eth0-output
  host-eth0 
  IP4: 02:42:ac:13:00:04 -> 02:42:ac:13:00:03
  UDP: 172.19.0.4 -> 172.19.0.3
    tos 0x00, ttl 253, length 102, checksum 0x6559 dscp CS0 ecn NON_ECN
    fragment id 0x0000
  UDP: 832 -> 4789
    length 82, checksum 0x0000

Packet 1025

02:04:16:670129: virtio-input
  virtio: hw_if_index 7 next-index 4 vring 0 len 83
    hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
02:04:16:670138: ethernet-input
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
02:04:16:670142: l2-input
  l2-input: sw_if_index 7 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29
02:04:16:670144: l2-output
  l2-output: sw_if_index 6 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29 data 08 00 45 00 00 45 f6 91 40 00 40 06
02:04:16:670146: memif3/0-output
  memif3/0 
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
  TCP: 172.55.244.5 -> 172.55.252.1
    tos 0x00, ttl 64, length 69, checksum 0xfbaa dscp CS0 ecn NON_ECN
    fragment id 0xf691, flags DONT_FRAGMENT
  TCP: 5000 -> 40146
    seq. 0x620777c5 ack 0xfc10a695
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 502, checksum 0x1fed

Packet 1026

02:04:16:670129: virtio-input
  virtio: hw_if_index 7 next-index 4 vring 0 len 265
    hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
02:04:16:670138: ethernet-input
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
02:04:16:670142: l2-input
  l2-input: sw_if_index 7 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29
02:04:16:670144: l2-output
  l2-output: sw_if_index 6 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29 data 08 00 45 00 00 fb f6 92 40 00 40 06
02:04:16:670146: memif3/0-output
  memif3/0 
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
  TCP: 172.55.244.5 -> 172.55.252.1
    tos 0x00, ttl 64, length 251, checksum 0xfaf3 dscp CS0 ecn NON_ECN
    fragment id 0xf692, flags DONT_FRAGMENT
  TCP: 5000 -> 40146
    seq. 0x620777d6 ack 0xfc10a695
    flags 0x19 FIN PSH ACK, tcp header: 32 bytes
    window 502, checksum 0xdbdf

Packet 1027

02:04:16:671236: memif-input
  memif: hw_if_index 2 next-index 4
    slot: ring 0
02:04:16:671239: ethernet-input
  IP4: 02:fe:7c:39:0d:4a -> 02:fe:af:46:8f:24
02:04:16:671241: l2-input
  l2-input: sw_if_index 2 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a
02:04:16:671242: l2-output
  l2-output: sw_if_index 3 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a data 08 00 45 00 00 45 f6 91 40 00 3f 06
02:04:16:671243: vxlan4-encap
  VXLAN encap to vxlan_tunnel0 vni 2
02:04:16:671245: ip4-rewrite
  tx_sw_if_index 1 dpo-idx 15 : ipv4 via 172.19.0.3 host-eth0: mtu:9000 0242ac1300030242ac1300040800 flow hash: 0x13484003
  00000000: 0242ac1300030242ac13000408004500007700000000fd116548ac130004ac13
  00000020: 0003034012b500630000080000000000020002feaf468f2402fe7c39
02:04:16:671246: host-eth0-output
  host-eth0 
  IP4: 02:42:ac:13:00:04 -> 02:42:ac:13:00:03
  UDP: 172.19.0.4 -> 172.19.0.3
    tos 0x00, ttl 253, length 119, checksum 0x6548 dscp CS0 ecn NON_ECN
    fragment id 0x0000
  UDP: 832 -> 4789
    length 99, checksum 0x0000

Packet 1028

02:04:16:671236: memif-input
  memif: hw_if_index 2 next-index 4
    slot: ring 0
02:04:16:671239: ethernet-input
  IP4: 02:fe:7c:39:0d:4a -> 02:fe:af:46:8f:24
02:04:16:671241: l2-input
  l2-input: sw_if_index 2 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a
02:04:16:671242: l2-output
  l2-output: sw_if_index 3 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a data 08 00 45 00 00 fb f6 92 40 00 3f 06
02:04:16:671243: vxlan4-encap
  VXLAN encap to vxlan_tunnel0 vni 2
02:04:16:671245: ip4-rewrite
  tx_sw_if_index 1 dpo-idx 15 : ipv4 via 172.19.0.3 host-eth0: mtu:9000 0242ac1300030242ac1300040800 flow hash: 0x13484003
  00000000: 0242ac1300030242ac13000408004500012d00000000fd116492ac130004ac13
  00000020: 0003034012b501190000080000000000020002feaf468f2402fe7c39
02:04:16:671246: host-eth0-output
  host-eth0 
  IP4: 02:42:ac:13:00:04 -> 02:42:ac:13:00:03
  UDP: 172.19.0.4 -> 172.19.0.3
    tos 0x00, ttl 253, length 301, checksum 0x6492 dscp CS0 ecn NON_ECN
    fragment id 0x0000
  UDP: 832 -> 4789
    length 281, checksum 0x0000

Packet 1029

02:04:16:676792: memif-input
  memif: hw_if_index 6 next-index 4
    slot: ring 0
02:04:16:676798: ethernet-input
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
02:04:16:676802: l2-input
  l2-input: sw_if_index 6 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4
02:04:16:676803: l2-output
  l2-output: sw_if_index 7 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4 data 08 00 45 00 00 34 28 32 40 00 3e 06
02:04:16:676805: tap0-output
  tap0 
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
  TCP: 172.55.252.1 -> 172.55.244.5
    tos 0x00, ttl 62, length 52, checksum 0xcc1b dscp CS0 ecn NON_ECN
    fragment id 0x2832, flags DONT_FRAGMENT
  TCP: 40146 -> 5000
    seq. 0xfc10a695 ack 0x620777d6
    flags 0x10 ACK, tcp header: 32 bytes
    window 507, checksum 0xdf3d

Packet 1030

02:04:16:676792: memif-input
  memif: hw_if_index 6 next-index 4
    slot: ring 0
02:04:16:676798: ethernet-input
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
02:04:16:676802: l2-input
  l2-input: sw_if_index 6 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4
02:04:16:676803: l2-output
  l2-output: sw_if_index 7 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4 data 08 00 45 00 00 34 28 33 40 00 3e 06
02:04:16:676805: tap0-output
  tap0 
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
  TCP: 172.55.252.1 -> 172.55.244.5
    tos 0x00, ttl 62, length 52, checksum 0xcc1a dscp CS0 ecn NON_ECN
    fragment id 0x2833, flags DONT_FRAGMENT
  TCP: 40146 -> 5000
    seq. 0xfc10a695 ack 0x6207789e
    flags 0x11 FIN ACK, tcp header: 32 bytes
    window 506, checksum 0xde74

Packet 1031

02:04:16:677989: virtio-input
  virtio: hw_if_index 7 next-index 4 vring 0 len 66
    hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
02:04:16:677995: ethernet-input
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
02:04:16:678004: l2-input
  l2-input: sw_if_index 7 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29
02:04:16:678032: l2-output
  l2-output: sw_if_index 6 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29 data 08 00 45 00 00 34 f6 93 40 00 40 06
02:04:16:678036: memif3/0-output
  memif3/0 
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
  TCP: 172.55.244.5 -> 172.55.252.1
    tos 0x00, ttl 64, length 52, checksum 0xfbb9 dscp CS0 ecn NON_ECN
    fragment id 0xf693, flags DONT_FRAGMENT
  TCP: 5000 -> 40146
    seq. 0x6207789e ack 0xfc10a696
    flags 0x10 ACK, tcp header: 32 bytes
    window 502, checksum 0xde71

Packet 1032

02:04:16:679124: memif-input
  memif: hw_if_index 2 next-index 4
    slot: ring 0
02:04:16:679129: ethernet-input
  IP4: 02:fe:7c:39:0d:4a -> 02:fe:af:46:8f:24
02:04:16:679135: l2-input
  l2-input: sw_if_index 2 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a
02:04:16:679138: l2-output
  l2-output: sw_if_index 3 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a data 08 00 45 00 00 34 f6 93 40 00 3f 06
02:04:16:679140: vxlan4-encap
  VXLAN encap to vxlan_tunnel0 vni 2
02:04:16:679142: ip4-rewrite
  tx_sw_if_index 1 dpo-idx 15 : ipv4 via 172.19.0.3 host-eth0: mtu:9000 0242ac1300030242ac1300040800 flow hash: 0x13484003
  00000000: 0242ac1300030242ac13000408004500006600000000fd116559ac130004ac13
  00000020: 0003034012b500520000080000000000020002feaf468f2402fe7c39
02:04:16:679144: host-eth0-output
  host-eth0 
  IP4: 02:42:ac:13:00:04 -> 02:42:ac:13:00:03
  UDP: 172.19.0.4 -> 172.19.0.3
    tos 0x00, ttl 253, length 102, checksum 0x6559 dscp CS0 ecn NON_ECN
    fragment id 0x0000
  UDP: 832 -> 4789
    length 82, checksum 0x0000

Packet 1033

02:04:17:034809: virtio-input
  virtio: hw_if_index 7 next-index 4 vring 0 len 74
    hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
02:04:17:034815: ethernet-input
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
02:04:17:034819: l2-input
  l2-input: sw_if_index 7 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29
02:04:17:034822: l2-output
  l2-output: sw_if_index 6 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29 data 08 00 45 00 00 3c 18 15 40 00 40 06
02:04:17:034824: memif3/0-output
  memif3/0 
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
  TCP: 172.55.244.5 -> 172.55.252.1
    tos 0x00, ttl 64, length 60, checksum 0xda30 dscp CS0 ecn NON_ECN
    fragment id 0x1815, flags DONT_FRAGMENT
  TCP: 47630 -> 5000
    seq. 0x2a4221e1 ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 64860, checksum 0x40fa

Packet 1034

02:04:17:035973: memif-input
  memif: hw_if_index 2 next-index 4
    slot: ring 0
02:04:17:035978: ethernet-input
  IP4: 02:fe:7c:39:0d:4a -> 02:fe:af:46:8f:24
02:04:17:035986: l2-input
  l2-input: sw_if_index 2 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a
02:04:17:035995: l2-output
  l2-output: sw_if_index 3 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a data 08 00 45 00 00 3c 18 15 40 00 3f 06
02:04:17:035997: vxlan4-encap
  VXLAN encap to vxlan_tunnel0 vni 2
02:04:17:036000: ip4-rewrite
  tx_sw_if_index 1 dpo-idx 15 : ipv4 via 172.19.0.3 host-eth0: mtu:9000 0242ac1300030242ac1300040800 flow hash: 0x317cc455
  00000000: 0242ac1300030242ac13000408004500006e00000000fd116551ac130004ac13
  00000020: 000355c412b5005a0000080000000000020002feaf468f2402fe7c39
02:04:17:036003: host-eth0-output
  host-eth0 
  IP4: 02:42:ac:13:00:04 -> 02:42:ac:13:00:03
  UDP: 172.19.0.4 -> 172.19.0.3
    tos 0x00, ttl 253, length 110, checksum 0x6551 dscp CS0 ecn NON_ECN
    fragment id 0x0000
  UDP: 21956 -> 4789
    length 90, checksum 0x0000

Packet 1035

02:04:17:041410: memif-input
  memif: hw_if_index 6 next-index 4
    slot: ring 0
02:04:17:041413: ethernet-input
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
02:04:17:041414: l2-input
  l2-input: sw_if_index 6 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4
02:04:17:041415: l2-output
  l2-output: sw_if_index 7 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4 data 08 00 45 00 00 3c 00 00 40 00 3e 06
02:04:17:041415: tap0-output
  tap0 
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
  TCP: 172.55.252.1 -> 172.55.244.5
    tos 0x00, ttl 62, length 60, checksum 0xf445 dscp CS0 ecn NON_ECN
    fragment id 0x0000, flags DONT_FRAGMENT
  TCP: 5000 -> 47630
    seq. 0x19d09b3f ack 0x2a4221e2
    flags 0x12 SYN ACK, tcp header: 40 bytes
    window 64308, checksum 0x12a3

Packet 1036

02:04:17:042515: virtio-input
  virtio: hw_if_index 7 next-index 4 vring 0 len 66
    hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
02:04:17:042518: ethernet-input
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
02:04:17:042524: l2-input
  l2-input: sw_if_index 7 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29
02:04:17:042530: l2-output
  l2-output: sw_if_index 6 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29 data 08 00 45 00 00 34 18 16 40 00 40 06
02:04:17:042531: memif3/0-output
  memif3/0 
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
  TCP: 172.55.244.5 -> 172.55.252.1
    tos 0x00, ttl 64, length 52, checksum 0xda37 dscp CS0 ecn NON_ECN
    fragment id 0x1816, flags DONT_FRAGMENT
  TCP: 47630 -> 5000
    seq. 0x2a4221e2 ack 0x19d09b40
    flags 0x10 ACK, tcp header: 32 bytes
    window 507, checksum 0x3a71

Packet 1037

02:04:17:042515: virtio-input
  virtio: hw_if_index 7 next-index 4 vring 0 len 152
    hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
02:04:17:042518: ethernet-input
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
02:04:17:042524: l2-input
  l2-input: sw_if_index 7 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29
02:04:17:042530: l2-output
  l2-output: sw_if_index 6 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29 data 08 00 45 00 00 8a 18 17 40 00 40 06
02:04:17:042531: memif3/0-output
  memif3/0 
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
  TCP: 172.55.244.5 -> 172.55.252.1
    tos 0x00, ttl 64, length 138, checksum 0xd9e0 dscp CS0 ecn NON_ECN
    fragment id 0x1817, flags DONT_FRAGMENT
  TCP: 47630 -> 5000
    seq. 0x2a4221e2 ack 0x19d09b40
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 507, checksum 0x5865

Packet 1038

02:04:17:043573: memif-input
  memif: hw_if_index 2 next-index 4
    slot: ring 0
02:04:17:043576: ethernet-input
  IP4: 02:fe:7c:39:0d:4a -> 02:fe:af:46:8f:24
02:04:17:043577: l2-input
  l2-input: sw_if_index 2 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a
02:04:17:043578: l2-output
  l2-output: sw_if_index 3 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a data 08 00 45 00 00 34 18 16 40 00 3f 06
02:04:17:043578: vxlan4-encap
  VXLAN encap to vxlan_tunnel0 vni 2
02:04:17:043580: ip4-rewrite
  tx_sw_if_index 1 dpo-idx 15 : ipv4 via 172.19.0.3 host-eth0: mtu:9000 0242ac1300030242ac1300040800 flow hash: 0x317cc455
  00000000: 0242ac1300030242ac13000408004500006600000000fd116559ac130004ac13
  00000020: 000355c412b500520000080000000000020002feaf468f2402fe7c39
02:04:17:043581: host-eth0-output
  host-eth0 
  IP4: 02:42:ac:13:00:04 -> 02:42:ac:13:00:03
  UDP: 172.19.0.4 -> 172.19.0.3
    tos 0x00, ttl 253, length 102, checksum 0x6559 dscp CS0 ecn NON_ECN
    fragment id 0x0000
  UDP: 21956 -> 4789
    length 82, checksum 0x0000

Packet 1039

02:04:17:043573: memif-input
  memif: hw_if_index 2 next-index 4
    slot: ring 0
02:04:17:043576: ethernet-input
  IP4: 02:fe:7c:39:0d:4a -> 02:fe:af:46:8f:24
02:04:17:043577: l2-input
  l2-input: sw_if_index 2 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a
02:04:17:043578: l2-output
  l2-output: sw_if_index 3 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a data 08 00 45 00 00 8a 18 17 40 00 3f 06
02:04:17:043578: vxlan4-encap
  VXLAN encap to vxlan_tunnel0 vni 2
02:04:17:043580: ip4-rewrite
  tx_sw_if_index 1 dpo-idx 15 : ipv4 via 172.19.0.3 host-eth0: mtu:9000 0242ac1300030242ac1300040800 flow hash: 0x317cc455
  00000000: 0242ac1300030242ac1300040800450000bc00000000fd116503ac130004ac13
  00000020: 000355c412b500a80000080000000000020002feaf468f2402fe7c39
02:04:17:043581: host-eth0-output
  host-eth0 
  IP4: 02:42:ac:13:00:04 -> 02:42:ac:13:00:03
  UDP: 172.19.0.4 -> 172.19.0.3
    tos 0x00, ttl 253, length 188, checksum 0x6503 dscp CS0 ecn NON_ECN
    fragment id 0x0000
  UDP: 21956 -> 4789
    length 168, checksum 0x0000

Packet 1040

02:04:17:049164: memif-input
  memif: hw_if_index 6 next-index 4
    slot: ring 0
02:04:17:049169: ethernet-input
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
02:04:17:049172: l2-input
  l2-input: sw_if_index 6 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4
02:04:17:049173: l2-output
  l2-output: sw_if_index 7 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4 data 08 00 45 00 00 34 3f 67 40 00 3e 06
02:04:17:049175: tap0-output
  tap0 
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
  TCP: 172.55.252.1 -> 172.55.244.5
    tos 0x00, ttl 62, length 52, checksum 0xb4e6 dscp CS0 ecn NON_ECN
    fragment id 0x3f67, flags DONT_FRAGMENT
  TCP: 5000 -> 47630
    seq. 0x19d09b40 ack 0x2a422238
    flags 0x10 ACK, tcp header: 32 bytes
    window 502, checksum 0x3a17

Packet 1041

02:04:17:168388: memif-input
  memif: hw_if_index 6 next-index 4
    slot: ring 0
02:04:17:168394: ethernet-input
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
02:04:17:168398: l2-input
  l2-input: sw_if_index 6 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4
02:04:17:168400: l2-output
  l2-output: sw_if_index 7 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4 data 08 00 45 00 00 45 3f 68 40 00 3e 06
02:04:17:168401: tap0-output
  tap0 
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
  TCP: 172.55.252.1 -> 172.55.244.5
    tos 0x00, ttl 62, length 69, checksum 0xb4d4 dscp CS0 ecn NON_ECN
    fragment id 0x3f68, flags DONT_FRAGMENT
  TCP: 5000 -> 47630
    seq. 0x19d09b40 ack 0x2a422238
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 502, checksum 0x79c3

Packet 1042

02:04:17:168388: memif-input
  memif: hw_if_index 6 next-index 4
    slot: ring 0
02:04:17:168394: ethernet-input
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
02:04:17:168398: l2-input
  l2-input: sw_if_index 6 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4
02:04:17:168400: l2-output
  l2-output: sw_if_index 7 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4 data 08 00 45 00 00 fb 3f 69 40 00 3e 06
02:04:17:168401: tap0-output
  tap0 
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
  TCP: 172.55.252.1 -> 172.55.244.5
    tos 0x00, ttl 62, length 251, checksum 0xb41d dscp CS0 ecn NON_ECN
    fragment id 0x3f69, flags DONT_FRAGMENT
  TCP: 5000 -> 47630
    seq. 0x19d09b51 ack 0x2a422238
    flags 0x19 FIN PSH ACK, tcp header: 32 bytes
    window 502, checksum 0xe556

Packet 1043

02:04:17:169639: virtio-input
  virtio: hw_if_index 7 next-index 4 vring 0 len 66
    hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
02:04:17:169645: ethernet-input
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
02:04:17:169657: l2-input
  l2-input: sw_if_index 7 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29
02:04:17:170439: l2-output
  l2-output: sw_if_index 6 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29 data 08 00 45 00 00 34 18 18 40 00 40 06
02:04:17:170444: memif3/0-output
  memif3/0 
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
  TCP: 172.55.244.5 -> 172.55.252.1
    tos 0x00, ttl 64, length 52, checksum 0xda35 dscp CS0 ecn NON_ECN
    fragment id 0x1818, flags DONT_FRAGMENT
  TCP: 47630 -> 5000
    seq. 0x2a422238 ack 0x19d09b51
    flags 0x10 ACK, tcp header: 32 bytes
    window 507, checksum 0x390d

Packet 1044

02:04:17:169639: virtio-input
  virtio: hw_if_index 7 next-index 4 vring 0 len 66
    hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
02:04:17:169645: ethernet-input
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
02:04:17:169657: l2-input
  l2-input: sw_if_index 7 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29
02:04:17:170439: l2-output
  l2-output: sw_if_index 6 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29 data 08 00 45 00 00 34 18 19 40 00 40 06
02:04:17:170444: memif3/0-output
  memif3/0 
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
  TCP: 172.55.244.5 -> 172.55.252.1
    tos 0x00, ttl 64, length 52, checksum 0xda34 dscp CS0 ecn NON_ECN
    fragment id 0x1819, flags DONT_FRAGMENT
  TCP: 47630 -> 5000
    seq. 0x2a422238 ack 0x19d09c19
    flags 0x11 FIN ACK, tcp header: 32 bytes
    window 506, checksum 0x3844

Packet 1045

02:04:17:173374: memif-input
  memif: hw_if_index 2 next-index 4
    slot: ring 0
02:04:17:173382: ethernet-input
  IP4: 02:fe:7c:39:0d:4a -> 02:fe:af:46:8f:24
02:04:17:173394: l2-input
  l2-input: sw_if_index 2 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a
02:04:17:173404: l2-output
  l2-output: sw_if_index 3 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a data 08 00 45 00 00 34 18 18 40 00 3f 06
02:04:17:173408: vxlan4-encap
  VXLAN encap to vxlan_tunnel0 vni 2
02:04:17:173412: ip4-rewrite
  tx_sw_if_index 1 dpo-idx 15 : ipv4 via 172.19.0.3 host-eth0: mtu:9000 0242ac1300030242ac1300040800 flow hash: 0x317cc455
  00000000: 0242ac1300030242ac13000408004500006600000000fd116559ac130004ac13
  00000020: 000355c412b500520000080000000000020002feaf468f2402fe7c39
02:04:17:173415: host-eth0-output
  host-eth0 
  IP4: 02:42:ac:13:00:04 -> 02:42:ac:13:00:03
  UDP: 172.19.0.4 -> 172.19.0.3
    tos 0x00, ttl 253, length 102, checksum 0x6559 dscp CS0 ecn NON_ECN
    fragment id 0x0000
  UDP: 21956 -> 4789
    length 82, checksum 0x0000

Packet 1046

02:04:17:173374: memif-input
  memif: hw_if_index 2 next-index 4
    slot: ring 0
02:04:17:173382: ethernet-input
  IP4: 02:fe:7c:39:0d:4a -> 02:fe:af:46:8f:24
02:04:17:173394: l2-input
  l2-input: sw_if_index 2 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a
02:04:17:173404: l2-output
  l2-output: sw_if_index 3 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a data 08 00 45 00 00 34 18 19 40 00 3f 06
02:04:17:173408: vxlan4-encap
  VXLAN encap to vxlan_tunnel0 vni 2
02:04:17:173412: ip4-rewrite
  tx_sw_if_index 1 dpo-idx 15 : ipv4 via 172.19.0.3 host-eth0: mtu:9000 0242ac1300030242ac1300040800 flow hash: 0x317cc455
  00000000: 0242ac1300030242ac13000408004500006600000000fd116559ac130004ac13
  00000020: 000355c412b500520000080000000000020002feaf468f2402fe7c39
02:04:17:173415: host-eth0-output
  host-eth0 
  IP4: 02:42:ac:13:00:04 -> 02:42:ac:13:00:03
  UDP: 172.19.0.4 -> 172.19.0.3
    tos 0x00, ttl 253, length 102, checksum 0x6559 dscp CS0 ecn NON_ECN
    fragment id 0x0000
  UDP: 21956 -> 4789
    length 82, checksum 0x0000

Packet 1047

02:04:17:180105: memif-input
  memif: hw_if_index 6 next-index 4
    slot: ring 0
02:04:17:180111: ethernet-input
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
02:04:17:180116: l2-input
  l2-input: sw_if_index 6 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4
02:04:17:180118: l2-output
  l2-output: sw_if_index 7 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4 data 08 00 45 00 00 34 3f 6a 40 00 3e 06
02:04:17:180119: tap0-output
  tap0 
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
  TCP: 172.55.252.1 -> 172.55.244.5
    tos 0x00, ttl 62, length 52, checksum 0xb4e3 dscp CS0 ecn NON_ECN
    fragment id 0x3f6a, flags DONT_FRAGMENT
  TCP: 5000 -> 47630
    seq. 0x19d09c19 ack 0x2a422239
    flags 0x10 ACK, tcp header: 32 bytes
    window 502, checksum 0x383b

Packet 1048

02:04:17:294376: virtio-input
  virtio: hw_if_index 7 next-index 4 vring 0 len 74
    hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
02:04:17:294381: ethernet-input
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
02:04:17:294391: l2-input
  l2-input: sw_if_index 7 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29
02:04:17:294398: l2-output
  l2-output: sw_if_index 6 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29 data 08 00 45 00 00 3c 76 e0 40 00 40 06
02:04:17:294400: memif3/0-output
  memif3/0 
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
  TCP: 172.55.244.5 -> 172.55.252.1
    tos 0x00, ttl 64, length 60, checksum 0x7b65 dscp CS0 ecn NON_ECN
    fragment id 0x76e0, flags DONT_FRAGMENT
  TCP: 47652 -> 5000
    seq. 0x3ac62510 ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 64860, checksum 0x2c2e

Packet 1049

02:04:17:295473: memif-input
  memif: hw_if_index 2 next-index 4
    slot: ring 0
02:04:17:295478: ethernet-input
  IP4: 02:fe:7c:39:0d:4a -> 02:fe:af:46:8f:24
02:04:17:295480: l2-input
  l2-input: sw_if_index 2 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a
02:04:17:295481: l2-output
  l2-output: sw_if_index 3 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a data 08 00 45 00 00 3c 76 e0 40 00 3f 06
02:04:17:295482: vxlan4-encap
  VXLAN encap to vxlan_tunnel0 vni 2
02:04:17:295484: ip4-rewrite
  tx_sw_if_index 1 dpo-idx 15 : ipv4 via 172.19.0.3 host-eth0: mtu:9000 0242ac1300030242ac1300040800 flow hash: 0x1305eec2
  00000000: 0242ac1300030242ac13000408004500006e00000000fd116551ac130004ac13
  00000020: 0003c2ee12b5005a0000080000000000020002feaf468f2402fe7c39
02:04:17:295486: host-eth0-output
  host-eth0 
  IP4: 02:42:ac:13:00:04 -> 02:42:ac:13:00:03
  UDP: 172.19.0.4 -> 172.19.0.3
    tos 0x00, ttl 253, length 110, checksum 0x6551 dscp CS0 ecn NON_ECN
    fragment id 0x0000
  UDP: 49902 -> 4789
    length 90, checksum 0x0000

Packet 1050

02:04:17:301466: memif-input
  memif: hw_if_index 6 next-index 4
    slot: ring 0
02:04:17:301472: ethernet-input
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
02:04:17:301477: l2-input
  l2-input: sw_if_index 6 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4
02:04:17:301479: l2-output
  l2-output: sw_if_index 7 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4 data 08 00 45 00 00 3c 00 00 40 00 3e 06
02:04:17:301481: tap0-output
  tap0 
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
  TCP: 172.55.252.1 -> 172.55.244.5
    tos 0x00, ttl 62, length 60, checksum 0xf445 dscp CS0 ecn NON_ECN
    fragment id 0x0000, flags DONT_FRAGMENT
  TCP: 5000 -> 47652
    seq. 0xc1974ec8 ack 0x3ac62511
    flags 0x12 SYN ACK, tcp header: 40 bytes
    window 64308, checksum 0xa183

Packet 1051

02:04:17:302817: virtio-input
  virtio: hw_if_index 7 next-index 4 vring 0 len 66
    hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
02:04:17:302825: ethernet-input
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
02:04:17:302831: l2-input
  l2-input: sw_if_index 7 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29
02:04:17:302834: l2-output
  l2-output: sw_if_index 6 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29 data 08 00 45 00 00 34 76 e1 40 00 40 06
02:04:17:302836: memif3/0-output
  memif3/0 
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
  TCP: 172.55.244.5 -> 172.55.252.1
    tos 0x00, ttl 64, length 52, checksum 0x7b6c dscp CS0 ecn NON_ECN
    fragment id 0x76e1, flags DONT_FRAGMENT
  TCP: 47652 -> 5000
    seq. 0x3ac62511 ack 0xc1974ec9
    flags 0x10 ACK, tcp header: 32 bytes
    window 507, checksum 0xc950

Packet 1052

02:04:17:302817: virtio-input
  virtio: hw_if_index 7 next-index 4 vring 0 len 174
    hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
02:04:17:302825: ethernet-input
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
02:04:17:302831: l2-input
  l2-input: sw_if_index 7 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29
02:04:17:302834: l2-output
  l2-output: sw_if_index 6 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29 data 08 00 45 00 00 a0 76 e2 40 00 40 06
02:04:17:302836: memif3/0-output
  memif3/0 
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
  TCP: 172.55.244.5 -> 172.55.252.1
    tos 0x00, ttl 64, length 160, checksum 0x7aff dscp CS0 ecn NON_ECN
    fragment id 0x76e2, flags DONT_FRAGMENT
  TCP: 47652 -> 5000
    seq. 0x3ac62511 ack 0xc1974ec9
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 507, checksum 0x2655

Packet 1053

02:04:17:303891: memif-input
  memif: hw_if_index 2 next-index 4
    slot: ring 0
02:04:17:303895: ethernet-input
  IP4: 02:fe:7c:39:0d:4a -> 02:fe:af:46:8f:24
02:04:17:303902: l2-input
  l2-input: sw_if_index 2 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a
02:04:17:303909: l2-output
  l2-output: sw_if_index 3 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a data 08 00 45 00 00 34 76 e1 40 00 3f 06
02:04:17:303910: vxlan4-encap
  VXLAN encap to vxlan_tunnel0 vni 2
02:04:17:303914: ip4-rewrite
  tx_sw_if_index 1 dpo-idx 15 : ipv4 via 172.19.0.3 host-eth0: mtu:9000 0242ac1300030242ac1300040800 flow hash: 0x1305eec2
  00000000: 0242ac1300030242ac13000408004500006600000000fd116559ac130004ac13
  00000020: 0003c2ee12b500520000080000000000020002feaf468f2402fe7c39
02:04:17:303915: host-eth0-output
  host-eth0 
  IP4: 02:42:ac:13:00:04 -> 02:42:ac:13:00:03
  UDP: 172.19.0.4 -> 172.19.0.3
    tos 0x00, ttl 253, length 102, checksum 0x6559 dscp CS0 ecn NON_ECN
    fragment id 0x0000
  UDP: 49902 -> 4789
    length 82, checksum 0x0000

Packet 1054

02:04:17:303891: memif-input
  memif: hw_if_index 2 next-index 4
    slot: ring 0
02:04:17:303895: ethernet-input
  IP4: 02:fe:7c:39:0d:4a -> 02:fe:af:46:8f:24
02:04:17:303902: l2-input
  l2-input: sw_if_index 2 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a
02:04:17:303909: l2-output
  l2-output: sw_if_index 3 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a data 08 00 45 00 00 a0 76 e2 40 00 3f 06
02:04:17:303910: vxlan4-encap
  VXLAN encap to vxlan_tunnel0 vni 2
02:04:17:303914: ip4-rewrite
  tx_sw_if_index 1 dpo-idx 15 : ipv4 via 172.19.0.3 host-eth0: mtu:9000 0242ac1300030242ac1300040800 flow hash: 0x1305eec2
  00000000: 0242ac1300030242ac1300040800450000d200000000fd1164edac130004ac13
  00000020: 0003c2ee12b500be0000080000000000020002feaf468f2402fe7c39
02:04:17:303915: host-eth0-output
  host-eth0 
  IP4: 02:42:ac:13:00:04 -> 02:42:ac:13:00:03
  UDP: 172.19.0.4 -> 172.19.0.3
    tos 0x00, ttl 253, length 210, checksum 0x64ed dscp CS0 ecn NON_ECN
    fragment id 0x0000
  UDP: 49902 -> 4789
    length 190, checksum 0x0000

Packet 1055

02:04:17:310466: memif-input
  memif: hw_if_index 6 next-index 4
    slot: ring 0
02:04:17:310474: ethernet-input
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
02:04:17:310479: l2-input
  l2-input: sw_if_index 6 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4
02:04:17:310480: l2-output
  l2-output: sw_if_index 7 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4 data 08 00 45 00 00 34 09 fd 40 00 3e 06
02:04:17:310482: tap0-output
  tap0 
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
  TCP: 172.55.252.1 -> 172.55.244.5
    tos 0x00, ttl 62, length 52, checksum 0xea50 dscp CS0 ecn NON_ECN
    fragment id 0x09fd, flags DONT_FRAGMENT
  TCP: 5000 -> 47652
    seq. 0xc1974ec9 ack 0x3ac6257d
    flags 0x10 ACK, tcp header: 32 bytes
    window 502, checksum 0xc8e1

Packet 1056

02:04:17:426003: memif-input
  memif: hw_if_index 6 next-index 4
    slot: ring 0
02:04:17:426007: ethernet-input
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
02:04:17:426009: l2-input
  l2-input: sw_if_index 6 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4
02:04:17:426010: l2-output
  l2-output: sw_if_index 7 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4 data 08 00 45 00 00 45 09 fe 40 00 3e 06
02:04:17:426011: tap0-output
  tap0 
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
  TCP: 172.55.252.1 -> 172.55.244.5
    tos 0x00, ttl 62, length 69, checksum 0xea3e dscp CS0 ecn NON_ECN
    fragment id 0x09fe, flags DONT_FRAGMENT
  TCP: 5000 -> 47652
    seq. 0xc1974ec9 ack 0x3ac6257d
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 502, checksum 0x088f

Packet 1057

02:04:17:426003: memif-input
  memif: hw_if_index 6 next-index 4
    slot: ring 0
02:04:17:426007: ethernet-input
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
02:04:17:426009: l2-input
  l2-input: sw_if_index 6 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4
02:04:17:426010: l2-output
  l2-output: sw_if_index 7 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4 data 08 00 45 00 00 fb 09 ff 40 00 3e 06
02:04:17:426011: tap0-output
  tap0 
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
  TCP: 172.55.252.1 -> 172.55.244.5
    tos 0x00, ttl 62, length 251, checksum 0xe987 dscp CS0 ecn NON_ECN
    fragment id 0x09ff, flags DONT_FRAGMENT
  TCP: 5000 -> 47652
    seq. 0xc1974eda ack 0x3ac6257d
    flags 0x19 FIN PSH ACK, tcp header: 32 bytes
    window 502, checksum 0x7422

Packet 1058

02:04:17:427105: virtio-input
  virtio: hw_if_index 7 next-index 4 vring 0 len 66
    hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
02:04:17:427111: ethernet-input
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
02:04:17:427123: l2-input
  l2-input: sw_if_index 7 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29
02:04:17:427134: l2-output
  l2-output: sw_if_index 6 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29 data 08 00 45 00 00 34 76 e3 40 00 40 06
02:04:17:427136: memif3/0-output
  memif3/0 
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
  TCP: 172.55.244.5 -> 172.55.252.1
    tos 0x00, ttl 64, length 52, checksum 0x7b6a dscp CS0 ecn NON_ECN
    fragment id 0x76e3, flags DONT_FRAGMENT
  TCP: 47652 -> 5000
    seq. 0x3ac6257d ack 0xc1974eda
    flags 0x10 ACK, tcp header: 32 bytes
    window 507, checksum 0xc7d9

Packet 1059

02:04:17:427105: virtio-input
  virtio: hw_if_index 7 next-index 4 vring 0 len 66
    hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
02:04:17:427111: ethernet-input
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
02:04:17:427123: l2-input
  l2-input: sw_if_index 7 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29
02:04:17:427134: l2-output
  l2-output: sw_if_index 6 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29 data 08 00 45 00 00 34 76 e4 40 00 40 06
02:04:17:427136: memif3/0-output
  memif3/0 
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
  TCP: 172.55.244.5 -> 172.55.252.1
    tos 0x00, ttl 64, length 52, checksum 0x7b69 dscp CS0 ecn NON_ECN
    fragment id 0x76e4, flags DONT_FRAGMENT
  TCP: 47652 -> 5000
    seq. 0x3ac6257d ack 0xc1974fa2
    flags 0x11 FIN ACK, tcp header: 32 bytes
    window 506, checksum 0xc711

Packet 1060

02:04:17:428362: memif-input
  memif: hw_if_index 2 next-index 4
    slot: ring 0
02:04:17:428369: ethernet-input
  IP4: 02:fe:7c:39:0d:4a -> 02:fe:af:46:8f:24
02:04:17:428379: l2-input
  l2-input: sw_if_index 2 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a
02:04:17:428389: l2-output
  l2-output: sw_if_index 3 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a data 08 00 45 00 00 34 76 e3 40 00 3f 06
02:04:17:428391: vxlan4-encap
  VXLAN encap to vxlan_tunnel0 vni 2
02:04:17:428393: ip4-rewrite
  tx_sw_if_index 1 dpo-idx 15 : ipv4 via 172.19.0.3 host-eth0: mtu:9000 0242ac1300030242ac1300040800 flow hash: 0x1305eec2
  00000000: 0242ac1300030242ac13000408004500006600000000fd116559ac130004ac13
  00000020: 0003c2ee12b500520000080000000000020002feaf468f2402fe7c39
02:04:17:428395: host-eth0-output
  host-eth0 
  IP4: 02:42:ac:13:00:04 -> 02:42:ac:13:00:03
  UDP: 172.19.0.4 -> 172.19.0.3
    tos 0x00, ttl 253, length 102, checksum 0x6559 dscp CS0 ecn NON_ECN
    fragment id 0x0000
  UDP: 49902 -> 4789
    length 82, checksum 0x0000

Packet 1061

02:04:17:428362: memif-input
  memif: hw_if_index 2 next-index 4
    slot: ring 0
02:04:17:428369: ethernet-input
  IP4: 02:fe:7c:39:0d:4a -> 02:fe:af:46:8f:24
02:04:17:428379: l2-input
  l2-input: sw_if_index 2 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a
02:04:17:428389: l2-output
  l2-output: sw_if_index 3 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a data 08 00 45 00 00 34 76 e4 40 00 3f 06
02:04:17:428391: vxlan4-encap
  VXLAN encap to vxlan_tunnel0 vni 2
02:04:17:428393: ip4-rewrite
  tx_sw_if_index 1 dpo-idx 15 : ipv4 via 172.19.0.3 host-eth0: mtu:9000 0242ac1300030242ac1300040800 flow hash: 0x1305eec2
  00000000: 0242ac1300030242ac13000408004500006600000000fd116559ac130004ac13
  00000020: 0003c2ee12b500520000080000000000020002feaf468f2402fe7c39
02:04:17:428395: host-eth0-output
  host-eth0 
  IP4: 02:42:ac:13:00:04 -> 02:42:ac:13:00:03
  UDP: 172.19.0.4 -> 172.19.0.3
    tos 0x00, ttl 253, length 102, checksum 0x6559 dscp CS0 ecn NON_ECN
    fragment id 0x0000
  UDP: 49902 -> 4789
    length 82, checksum 0x0000

Packet 1062

02:04:17:434113: memif-input
  memif: hw_if_index 6 next-index 4
    slot: ring 0
02:04:17:434120: ethernet-input
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
02:04:17:434124: l2-input
  l2-input: sw_if_index 6 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4
02:04:17:434126: l2-output
  l2-output: sw_if_index 7 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4 data 08 00 45 00 00 34 0a 00 40 00 3e 06
02:04:17:434127: tap0-output
  tap0 
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
  TCP: 172.55.252.1 -> 172.55.244.5
    tos 0x00, ttl 62, length 52, checksum 0xea4d dscp CS0 ecn NON_ECN
    fragment id 0x0a00, flags DONT_FRAGMENT
  TCP: 5000 -> 47652
    seq. 0xc1974fa2 ack 0x3ac6257e
    flags 0x10 ACK, tcp header: 32 bytes
    window 502, checksum 0xc70d

Packet 1063

02:04:21:018673: memif-input
  memif: hw_if_index 6 next-index 4
    slot: ring 0
02:04:21:018677: ethernet-input
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
02:04:21:018679: l2-input
  l2-input: sw_if_index 6 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4
02:04:21:018680: l2-output
  l2-output: sw_if_index 7 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4 data 08 00 45 00 00 3c 0c ca 40 00 3e 06
02:04:21:018681: tap0-output
  tap0 
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
  TCP: 172.55.252.1 -> 172.55.244.5
    tos 0x00, ttl 62, length 60, checksum 0xe77b dscp CS0 ecn NON_ECN
    fragment id 0x0cca, flags DONT_FRAGMENT
  TCP: 40398 -> 5000
    seq. 0x17f4c2ef ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 64860, checksum 0xeb3f

Packet 1064

02:04:21:019748: virtio-input
  virtio: hw_if_index 7 next-index 4 vring 0 len 74
    hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
02:04:21:019751: ethernet-input
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
02:04:21:019752: l2-input
  l2-input: sw_if_index 7 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29
02:04:21:019753: l2-output
  l2-output: sw_if_index 6 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29 data 08 00 45 00 00 3c 00 00 40 00 40 06
02:04:21:019754: memif3/0-output
  memif3/0 
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
  TCP: 172.55.244.5 -> 172.55.252.1
    tos 0x00, ttl 64, length 60, checksum 0xf245 dscp CS0 ecn NON_ECN
    fragment id 0x0000, flags DONT_FRAGMENT
  TCP: 5000 -> 40398
    seq. 0x7c0c2ca1 ack 0x17f4c2f0
    flags 0x12 SYN ACK, tcp header: 40 bytes
    window 64308, checksum 0x8d72

Packet 1065

02:04:21:020772: memif-input
  memif: hw_if_index 2 next-index 4
    slot: ring 0
02:04:21:020774: ethernet-input
  IP4: 02:fe:7c:39:0d:4a -> 02:fe:af:46:8f:24
02:04:21:020775: l2-input
  l2-input: sw_if_index 2 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a
02:04:21:020776: l2-output
  l2-output: sw_if_index 3 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a data 08 00 45 00 00 3c 00 00 40 00 3f 06
02:04:21:020776: vxlan4-encap
  VXLAN encap to vxlan_tunnel0 vni 2
02:04:21:020777: ip4-rewrite
  tx_sw_if_index 1 dpo-idx 15 : ipv4 via 172.19.0.3 host-eth0: mtu:9000 0242ac1300030242ac1300040800 flow hash: 0x3c6baa56
  00000000: 0242ac1300030242ac13000408004500006e00000000fd116551ac130004ac13
  00000020: 000356aa12b5005a0000080000000000020002feaf468f2402fe7c39
02:04:21:020779: host-eth0-output
  host-eth0 
  IP4: 02:42:ac:13:00:04 -> 02:42:ac:13:00:03
  UDP: 172.19.0.4 -> 172.19.0.3
    tos 0x00, ttl 253, length 110, checksum 0x6551 dscp CS0 ecn NON_ECN
    fragment id 0x0000
  UDP: 22186 -> 4789
    length 90, checksum 0x0000

Packet 1066

02:04:21:026192: memif-input
  memif: hw_if_index 6 next-index 4
    slot: ring 0
02:04:21:026197: ethernet-input
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
02:04:21:026199: l2-input
  l2-input: sw_if_index 6 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4
02:04:21:026200: l2-output
  l2-output: sw_if_index 7 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4 data 08 00 45 00 00 34 0c cb 40 00 3e 06
02:04:21:026201: tap0-output
  tap0 
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
  TCP: 172.55.252.1 -> 172.55.244.5
    tos 0x00, ttl 62, length 52, checksum 0xe782 dscp CS0 ecn NON_ECN
    fragment id 0x0ccb, flags DONT_FRAGMENT
  TCP: 40398 -> 5000
    seq. 0x17f4c2f0 ack 0x7c0c2ca2
    flags 0x10 ACK, tcp header: 32 bytes
    window 507, checksum 0xb53f

Packet 1067

02:04:21:026192: memif-input
  memif: hw_if_index 6 next-index 4
    slot: ring 0
02:04:21:026197: ethernet-input
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
02:04:21:026199: l2-input
  l2-input: sw_if_index 6 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4
02:04:21:026200: l2-output
  l2-output: sw_if_index 7 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4 data 08 00 45 00 00 8a 0c cc 40 00 3e 06
02:04:21:026201: tap0-output
  tap0 
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
  TCP: 172.55.252.1 -> 172.55.244.5
    tos 0x00, ttl 62, length 138, checksum 0xe72b dscp CS0 ecn NON_ECN
    fragment id 0x0ccc, flags DONT_FRAGMENT
  TCP: 40398 -> 5000
    seq. 0x17f4c2f0 ack 0x7c0c2ca2
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 507, checksum 0xd42e

Packet 1068

02:04:21:027273: virtio-input
  virtio: hw_if_index 7 next-index 4 vring 0 len 66
    hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
02:04:21:027278: ethernet-input
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
02:04:21:027281: l2-input
  l2-input: sw_if_index 7 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29
02:04:21:027282: l2-output
  l2-output: sw_if_index 6 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29 data 08 00 45 00 00 34 af 56 40 00 40 06
02:04:21:027283: memif3/0-output
  memif3/0 
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
  TCP: 172.55.244.5 -> 172.55.252.1
    tos 0x00, ttl 64, length 52, checksum 0x42f7 dscp CS0 ecn NON_ECN
    fragment id 0xaf56, flags DONT_FRAGMENT
  TCP: 5000 -> 40398
    seq. 0x7c0c2ca2 ack 0x17f4c346
    flags 0x10 ACK, tcp header: 32 bytes
    window 502, checksum 0xb4e6

Packet 1069

02:04:21:029177: memif-input
  memif: hw_if_index 2 next-index 4
    slot: ring 0
02:04:21:029185: ethernet-input
  IP4: 02:fe:7c:39:0d:4a -> 02:fe:af:46:8f:24
02:04:21:029188: l2-input
  l2-input: sw_if_index 2 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a
02:04:21:029190: l2-output
  l2-output: sw_if_index 3 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a data 08 00 45 00 00 34 af 56 40 00 3f 06
02:04:21:029192: vxlan4-encap
  VXLAN encap to vxlan_tunnel0 vni 2
02:04:21:029195: ip4-rewrite
  tx_sw_if_index 1 dpo-idx 15 : ipv4 via 172.19.0.3 host-eth0: mtu:9000 0242ac1300030242ac1300040800 flow hash: 0x3c6baa56
  00000000: 0242ac1300030242ac13000408004500006600000000fd116559ac130004ac13
  00000020: 000356aa12b500520000080000000000020002feaf468f2402fe7c39
02:04:21:029197: host-eth0-output
  host-eth0 
  IP4: 02:42:ac:13:00:04 -> 02:42:ac:13:00:03
  UDP: 172.19.0.4 -> 172.19.0.3
    tos 0x00, ttl 253, length 102, checksum 0x6559 dscp CS0 ecn NON_ECN
    fragment id 0x0000
  UDP: 22186 -> 4789
    length 82, checksum 0x0000

Packet 1070

02:04:21:141580: virtio-input
  virtio: hw_if_index 7 next-index 4 vring 0 len 83
    hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
02:04:21:141587: ethernet-input
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
02:04:21:141590: l2-input
  l2-input: sw_if_index 7 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29
02:04:21:141592: l2-output
  l2-output: sw_if_index 6 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29 data 08 00 45 00 00 45 af 57 40 00 40 06
02:04:21:141594: memif3/0-output
  memif3/0 
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
  TCP: 172.55.244.5 -> 172.55.252.1
    tos 0x00, ttl 64, length 69, checksum 0x42e5 dscp CS0 ecn NON_ECN
    fragment id 0xaf57, flags DONT_FRAGMENT
  TCP: 5000 -> 40398
    seq. 0x7c0c2ca2 ack 0x17f4c346
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 502, checksum 0xf496

Packet 1071

02:04:21:141580: virtio-input
  virtio: hw_if_index 7 next-index 4 vring 0 len 265
    hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
02:04:21:141587: ethernet-input
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
02:04:21:141590: l2-input
  l2-input: sw_if_index 7 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29
02:04:21:141592: l2-output
  l2-output: sw_if_index 6 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29 data 08 00 45 00 00 fb af 58 40 00 40 06
02:04:21:141594: memif3/0-output
  memif3/0 
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
  TCP: 172.55.244.5 -> 172.55.252.1
    tos 0x00, ttl 64, length 251, checksum 0x422e dscp CS0 ecn NON_ECN
    fragment id 0xaf58, flags DONT_FRAGMENT
  TCP: 5000 -> 40398
    seq. 0x7c0c2cb3 ack 0x17f4c346
    flags 0x19 FIN PSH ACK, tcp header: 32 bytes
    window 502, checksum 0xaf8e

Packet 1072

02:04:21:142666: memif-input
  memif: hw_if_index 2 next-index 4
    slot: ring 0
02:04:21:142669: ethernet-input
  IP4: 02:fe:7c:39:0d:4a -> 02:fe:af:46:8f:24
02:04:21:142670: l2-input
  l2-input: sw_if_index 2 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a
02:04:21:142671: l2-output
  l2-output: sw_if_index 3 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a data 08 00 45 00 00 45 af 57 40 00 3f 06
02:04:21:142672: vxlan4-encap
  VXLAN encap to vxlan_tunnel0 vni 2
02:04:21:142674: ip4-rewrite
  tx_sw_if_index 1 dpo-idx 15 : ipv4 via 172.19.0.3 host-eth0: mtu:9000 0242ac1300030242ac1300040800 flow hash: 0x3c6baa56
  00000000: 0242ac1300030242ac13000408004500007700000000fd116548ac130004ac13
  00000020: 000356aa12b500630000080000000000020002feaf468f2402fe7c39
02:04:21:142676: host-eth0-output
  host-eth0 
  IP4: 02:42:ac:13:00:04 -> 02:42:ac:13:00:03
  UDP: 172.19.0.4 -> 172.19.0.3
    tos 0x00, ttl 253, length 119, checksum 0x6548 dscp CS0 ecn NON_ECN
    fragment id 0x0000
  UDP: 22186 -> 4789
    length 99, checksum 0x0000

Packet 1073

02:04:21:142666: memif-input
  memif: hw_if_index 2 next-index 4
    slot: ring 0
02:04:21:142669: ethernet-input
  IP4: 02:fe:7c:39:0d:4a -> 02:fe:af:46:8f:24
02:04:21:142670: l2-input
  l2-input: sw_if_index 2 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a
02:04:21:142671: l2-output
  l2-output: sw_if_index 3 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a data 08 00 45 00 00 fb af 58 40 00 3f 06
02:04:21:142672: vxlan4-encap
  VXLAN encap to vxlan_tunnel0 vni 2
02:04:21:142674: ip4-rewrite
  tx_sw_if_index 1 dpo-idx 15 : ipv4 via 172.19.0.3 host-eth0: mtu:9000 0242ac1300030242ac1300040800 flow hash: 0x3c6baa56
  00000000: 0242ac1300030242ac13000408004500012d00000000fd116492ac130004ac13
  00000020: 000356aa12b501190000080000000000020002feaf468f2402fe7c39
02:04:21:142676: host-eth0-output
  host-eth0 
  IP4: 02:42:ac:13:00:04 -> 02:42:ac:13:00:03
  UDP: 172.19.0.4 -> 172.19.0.3
    tos 0x00, ttl 253, length 301, checksum 0x6492 dscp CS0 ecn NON_ECN
    fragment id 0x0000
  UDP: 22186 -> 4789
    length 281, checksum 0x0000

Packet 1074

02:04:21:149856: memif-input
  memif: hw_if_index 6 next-index 4
    slot: ring 0
02:04:21:149863: ethernet-input
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
02:04:21:152399: l2-input
  l2-input: sw_if_index 6 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4
02:04:21:152404: l2-output
  l2-output: sw_if_index 7 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4 data 08 00 45 00 00 34 0c cd 40 00 3e 06
02:04:21:152407: tap0-output
  tap0 
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
  TCP: 172.55.252.1 -> 172.55.244.5
    tos 0x00, ttl 62, length 52, checksum 0xe780 dscp CS0 ecn NON_ECN
    fragment id 0x0ccd, flags DONT_FRAGMENT
  TCP: 40398 -> 5000
    seq. 0x17f4c346 ack 0x7c0c2cb3
    flags 0x10 ACK, tcp header: 32 bytes
    window 507, checksum 0xb3e4

Packet 1075

02:04:21:149856: memif-input
  memif: hw_if_index 6 next-index 4
    slot: ring 0
02:04:21:149863: ethernet-input
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
02:04:21:152399: l2-input
  l2-input: sw_if_index 6 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4
02:04:21:152404: l2-output
  l2-output: sw_if_index 7 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4 data 08 00 45 00 00 34 0c ce 40 00 3e 06
02:04:21:152407: tap0-output
  tap0 
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
  TCP: 172.55.252.1 -> 172.55.244.5
    tos 0x00, ttl 62, length 52, checksum 0xe77f dscp CS0 ecn NON_ECN
    fragment id 0x0cce, flags DONT_FRAGMENT
  TCP: 40398 -> 5000
    seq. 0x17f4c346 ack 0x7c0c2d7b
    flags 0x11 FIN ACK, tcp header: 32 bytes
    window 506, checksum 0xb31c

Packet 1076

02:04:21:153538: virtio-input
  virtio: hw_if_index 7 next-index 4 vring 0 len 66
    hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
02:04:21:153550: ethernet-input
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
02:04:21:153556: l2-input
  l2-input: sw_if_index 7 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29
02:04:21:153559: l2-output
  l2-output: sw_if_index 6 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29 data 08 00 45 00 00 34 af 59 40 00 40 06
02:04:21:153562: memif3/0-output
  memif3/0 
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
  TCP: 172.55.244.5 -> 172.55.252.1
    tos 0x00, ttl 64, length 52, checksum 0x42f4 dscp CS0 ecn NON_ECN
    fragment id 0xaf59, flags DONT_FRAGMENT
  TCP: 5000 -> 40398
    seq. 0x7c0c2d7b ack 0x17f4c347
    flags 0x10 ACK, tcp header: 32 bytes
    window 502, checksum 0xb314

Packet 1077

02:04:21:154650: memif-input
  memif: hw_if_index 2 next-index 4
    slot: ring 0
02:04:21:154656: ethernet-input
  IP4: 02:fe:7c:39:0d:4a -> 02:fe:af:46:8f:24
02:04:21:154659: l2-input
  l2-input: sw_if_index 2 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a
02:04:21:154661: l2-output
  l2-output: sw_if_index 3 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a data 08 00 45 00 00 34 af 59 40 00 3f 06
02:04:21:154662: vxlan4-encap
  VXLAN encap to vxlan_tunnel0 vni 2
02:04:21:154664: ip4-rewrite
  tx_sw_if_index 1 dpo-idx 15 : ipv4 via 172.19.0.3 host-eth0: mtu:9000 0242ac1300030242ac1300040800 flow hash: 0x3c6baa56
  00000000: 0242ac1300030242ac13000408004500006600000000fd116559ac130004ac13
  00000020: 000356aa12b500520000080000000000020002feaf468f2402fe7c39
02:04:21:154666: host-eth0-output
  host-eth0 
  IP4: 02:42:ac:13:00:04 -> 02:42:ac:13:00:03
  UDP: 172.19.0.4 -> 172.19.0.3
    tos 0x00, ttl 253, length 102, checksum 0x6559 dscp CS0 ecn NON_ECN
    fragment id 0x0000
  UDP: 22186 -> 4789
    length 82, checksum 0x0000

Packet 1078

02:04:22:424130: memif-input
  memif: hw_if_index 6 next-index 4
    slot: ring 0
02:04:22:424136: ethernet-input
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
02:04:22:424139: l2-input
  l2-input: sw_if_index 6 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4
02:04:22:424140: l2-output
  l2-output: sw_if_index 7 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4 data 08 00 45 00 00 3c a4 f5 40 00 3e 06
02:04:22:424141: tap0-output
  tap0 
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
  TCP: 172.55.252.1 -> 172.55.244.5
    tos 0x00, ttl 62, length 60, checksum 0x4f50 dscp CS0 ecn NON_ECN
    fragment id 0xa4f5, flags DONT_FRAGMENT
  TCP: 40470 -> 5000
    seq. 0x2ecebf77 ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 64860, checksum 0xd219

Packet 1079

02:04:22:425178: virtio-input
  virtio: hw_if_index 7 next-index 4 vring 0 len 74
    hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
02:04:22:425184: ethernet-input
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
02:04:22:425187: l2-input
  l2-input: sw_if_index 7 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29
02:04:22:425188: l2-output
  l2-output: sw_if_index 6 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29 data 08 00 45 00 00 3c 00 00 40 00 40 06
02:04:22:425189: memif3/0-output
  memif3/0 
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
  TCP: 172.55.244.5 -> 172.55.252.1
    tos 0x00, ttl 64, length 60, checksum 0xf245 dscp CS0 ecn NON_ECN
    fragment id 0x0000, flags DONT_FRAGMENT
  TCP: 5000 -> 40470
    seq. 0x0867cd01 ack 0x2ecebf78
    flags 0x12 SYN ACK, tcp header: 40 bytes
    window 64308, checksum 0x4215

Packet 1080

02:04:22:426239: memif-input
  memif: hw_if_index 2 next-index 4
    slot: ring 0
02:04:22:426243: ethernet-input
  IP4: 02:fe:7c:39:0d:4a -> 02:fe:af:46:8f:24
02:04:22:426245: l2-input
  l2-input: sw_if_index 2 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a
02:04:22:426246: l2-output
  l2-output: sw_if_index 3 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a data 08 00 45 00 00 3c 00 00 40 00 3f 06
02:04:22:426247: vxlan4-encap
  VXLAN encap to vxlan_tunnel0 vni 2
02:04:22:426250: ip4-rewrite
  tx_sw_if_index 1 dpo-idx 15 : ipv4 via 172.19.0.3 host-eth0: mtu:9000 0242ac1300030242ac1300040800 flow hash: 0x993c6e68
  00000000: 0242ac1300030242ac13000408004500006e00000000fd116551ac130004ac13
  00000020: 0003686e12b5005a0000080000000000020002feaf468f2402fe7c39
02:04:22:426253: host-eth0-output
  host-eth0 
  IP4: 02:42:ac:13:00:04 -> 02:42:ac:13:00:03
  UDP: 172.19.0.4 -> 172.19.0.3
    tos 0x00, ttl 253, length 110, checksum 0x6551 dscp CS0 ecn NON_ECN
    fragment id 0x0000
  UDP: 26734 -> 4789
    length 90, checksum 0x0000

Packet 1081

02:04:22:431699: memif-input
  memif: hw_if_index 6 next-index 4
    slot: ring 0
02:04:22:431705: ethernet-input
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
02:04:22:431707: l2-input
  l2-input: sw_if_index 6 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4
02:04:22:431709: l2-output
  l2-output: sw_if_index 7 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4 data 08 00 45 00 00 34 a4 f6 40 00 3e 06
02:04:22:431710: tap0-output
  tap0 
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
  TCP: 172.55.252.1 -> 172.55.244.5
    tos 0x00, ttl 62, length 52, checksum 0x4f57 dscp CS0 ecn NON_ECN
    fragment id 0xa4f6, flags DONT_FRAGMENT
  TCP: 40470 -> 5000
    seq. 0x2ecebf78 ack 0x0867cd02
    flags 0x10 ACK, tcp header: 32 bytes
    window 507, checksum 0x69e2

Packet 1082

02:04:22:431699: memif-input
  memif: hw_if_index 6 next-index 4
    slot: ring 0
02:04:22:431705: ethernet-input
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
02:04:22:431707: l2-input
  l2-input: sw_if_index 6 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4
02:04:22:431709: l2-output
  l2-output: sw_if_index 7 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4 data 08 00 45 00 00 a0 a4 f7 40 00 3e 06
02:04:22:431710: tap0-output
  tap0 
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
  TCP: 172.55.252.1 -> 172.55.244.5
    tos 0x00, ttl 62, length 160, checksum 0x4eea dscp CS0 ecn NON_ECN
    fragment id 0xa4f7, flags DONT_FRAGMENT
  TCP: 40470 -> 5000
    seq. 0x2ecebf78 ack 0x0867cd02
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 507, checksum 0xc6e5

Packet 1083

02:04:22:433258: virtio-input
  virtio: hw_if_index 7 next-index 4 vring 0 len 66
    hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
02:04:22:433270: ethernet-input
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
02:04:22:433275: l2-input
  l2-input: sw_if_index 7 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29
02:04:22:433278: l2-output
  l2-output: sw_if_index 6 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29 data 08 00 45 00 00 34 cb b3 40 00 40 06
02:04:22:433280: memif3/0-output
  memif3/0 
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
  TCP: 172.55.244.5 -> 172.55.252.1
    tos 0x00, ttl 64, length 52, checksum 0x269a dscp CS0 ecn NON_ECN
    fragment id 0xcbb3, flags DONT_FRAGMENT
  TCP: 5000 -> 40470
    seq. 0x0867cd02 ack 0x2ecebfe4
    flags 0x10 ACK, tcp header: 32 bytes
    window 502, checksum 0x6973

Packet 1084

02:04:22:434469: memif-input
  memif: hw_if_index 2 next-index 4
    slot: ring 0
02:04:22:434478: ethernet-input
  IP4: 02:fe:7c:39:0d:4a -> 02:fe:af:46:8f:24
02:04:22:434482: l2-input
  l2-input: sw_if_index 2 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a
02:04:22:434484: l2-output
  l2-output: sw_if_index 3 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a data 08 00 45 00 00 34 cb b3 40 00 3f 06
02:04:22:434487: vxlan4-encap
  VXLAN encap to vxlan_tunnel0 vni 2
02:04:22:434490: ip4-rewrite
  tx_sw_if_index 1 dpo-idx 15 : ipv4 via 172.19.0.3 host-eth0: mtu:9000 0242ac1300030242ac1300040800 flow hash: 0x993c6e68
  00000000: 0242ac1300030242ac13000408004500006600000000fd116559ac130004ac13
  00000020: 0003686e12b500520000080000000000020002feaf468f2402fe7c39
02:04:22:434493: host-eth0-output
  host-eth0 
  IP4: 02:42:ac:13:00:04 -> 02:42:ac:13:00:03
  UDP: 172.19.0.4 -> 172.19.0.3
    tos 0x00, ttl 253, length 102, checksum 0x6559 dscp CS0 ecn NON_ECN
    fragment id 0x0000
  UDP: 26734 -> 4789
    length 82, checksum 0x0000

Packet 1085

02:04:22:544594: virtio-input
  virtio: hw_if_index 7 next-index 4 vring 0 len 83
    hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
02:04:22:544601: ethernet-input
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
02:04:22:544604: l2-input
  l2-input: sw_if_index 7 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29
02:04:22:544606: l2-output
  l2-output: sw_if_index 6 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29 data 08 00 45 00 00 45 cb b4 40 00 40 06
02:04:22:544608: memif3/0-output
  memif3/0 
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
  TCP: 172.55.244.5 -> 172.55.252.1
    tos 0x00, ttl 64, length 69, checksum 0x2688 dscp CS0 ecn NON_ECN
    fragment id 0xcbb4, flags DONT_FRAGMENT
  TCP: 5000 -> 40470
    seq. 0x0867cd02 ack 0x2ecebfe4
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 502, checksum 0xa926

Packet 1086

02:04:22:544594: virtio-input
  virtio: hw_if_index 7 next-index 4 vring 0 len 265
    hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
02:04:22:544601: ethernet-input
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
02:04:22:544604: l2-input
  l2-input: sw_if_index 7 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29
02:04:22:544606: l2-output
  l2-output: sw_if_index 6 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29 data 08 00 45 00 00 fb cb b5 40 00 40 06
02:04:22:544608: memif3/0-output
  memif3/0 
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
  TCP: 172.55.244.5 -> 172.55.252.1
    tos 0x00, ttl 64, length 251, checksum 0x25d1 dscp CS0 ecn NON_ECN
    fragment id 0xcbb5, flags DONT_FRAGMENT
  TCP: 5000 -> 40470
    seq. 0x0867cd13 ack 0x2ecebfe4
    flags 0x19 FIN PSH ACK, tcp header: 32 bytes
    window 502, checksum 0x641c

Packet 1087

02:04:22:545692: memif-input
  memif: hw_if_index 2 next-index 4
    slot: ring 0
02:04:22:545696: ethernet-input
  IP4: 02:fe:7c:39:0d:4a -> 02:fe:af:46:8f:24
02:04:22:545697: l2-input
  l2-input: sw_if_index 2 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a
02:04:22:545698: l2-output
  l2-output: sw_if_index 3 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a data 08 00 45 00 00 45 cb b4 40 00 3f 06
02:04:22:545699: vxlan4-encap
  VXLAN encap to vxlan_tunnel0 vni 2
02:04:22:545701: ip4-rewrite
  tx_sw_if_index 1 dpo-idx 15 : ipv4 via 172.19.0.3 host-eth0: mtu:9000 0242ac1300030242ac1300040800 flow hash: 0x993c6e68
  00000000: 0242ac1300030242ac13000408004500007700000000fd116548ac130004ac13
  00000020: 0003686e12b500630000080000000000020002feaf468f2402fe7c39
02:04:22:545703: host-eth0-output
  host-eth0 
  IP4: 02:42:ac:13:00:04 -> 02:42:ac:13:00:03
  UDP: 172.19.0.4 -> 172.19.0.3
    tos 0x00, ttl 253, length 119, checksum 0x6548 dscp CS0 ecn NON_ECN
    fragment id 0x0000
  UDP: 26734 -> 4789
    length 99, checksum 0x0000

Packet 1088

02:04:22:545692: memif-input
  memif: hw_if_index 2 next-index 4
    slot: ring 0
02:04:22:545696: ethernet-input
  IP4: 02:fe:7c:39:0d:4a -> 02:fe:af:46:8f:24
02:04:22:545697: l2-input
  l2-input: sw_if_index 2 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a
02:04:22:545698: l2-output
  l2-output: sw_if_index 3 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a data 08 00 45 00 00 fb cb b5 40 00 3f 06
02:04:22:545699: vxlan4-encap
  VXLAN encap to vxlan_tunnel0 vni 2
02:04:22:545701: ip4-rewrite
  tx_sw_if_index 1 dpo-idx 15 : ipv4 via 172.19.0.3 host-eth0: mtu:9000 0242ac1300030242ac1300040800 flow hash: 0x993c6e68
  00000000: 0242ac1300030242ac13000408004500012d00000000fd116492ac130004ac13
  00000020: 0003686e12b501190000080000000000020002feaf468f2402fe7c39
02:04:22:545703: host-eth0-output
  host-eth0 
  IP4: 02:42:ac:13:00:04 -> 02:42:ac:13:00:03
  UDP: 172.19.0.4 -> 172.19.0.3
    tos 0x00, ttl 253, length 301, checksum 0x6492 dscp CS0 ecn NON_ECN
    fragment id 0x0000
  UDP: 26734 -> 4789
    length 281, checksum 0x0000

Packet 1089

02:04:22:552535: memif-input
  memif: hw_if_index 6 next-index 4
    slot: ring 0
02:04:22:552540: ethernet-input
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
02:04:22:552544: l2-input
  l2-input: sw_if_index 6 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4
02:04:22:552546: l2-output
  l2-output: sw_if_index 7 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4 data 08 00 45 00 00 34 a4 f8 40 00 3e 06
02:04:22:552548: tap0-output
  tap0 
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
  TCP: 172.55.252.1 -> 172.55.244.5
    tos 0x00, ttl 62, length 52, checksum 0x4f55 dscp CS0 ecn NON_ECN
    fragment id 0xa4f8, flags DONT_FRAGMENT
  TCP: 40470 -> 5000
    seq. 0x2ecebfe4 ack 0x0867cd13
    flags 0x10 ACK, tcp header: 32 bytes
    window 507, checksum 0x6876

Packet 1090

02:04:22:552535: memif-input
  memif: hw_if_index 6 next-index 4
    slot: ring 0
02:04:22:552540: ethernet-input
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
02:04:22:552544: l2-input
  l2-input: sw_if_index 6 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4
02:04:22:552546: l2-output
  l2-output: sw_if_index 7 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4 data 08 00 45 00 00 34 a4 f9 40 00 3e 06
02:04:22:552548: tap0-output
  tap0 
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
  TCP: 172.55.252.1 -> 172.55.244.5
    tos 0x00, ttl 62, length 52, checksum 0x4f54 dscp CS0 ecn NON_ECN
    fragment id 0xa4f9, flags DONT_FRAGMENT
  TCP: 40470 -> 5000
    seq. 0x2ecebfe4 ack 0x0867cddb
    flags 0x11 FIN ACK, tcp header: 32 bytes
    window 506, checksum 0x67ad

Packet 1091

02:04:22:554227: virtio-input
  virtio: hw_if_index 7 next-index 4 vring 0 len 66
    hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
02:04:22:554239: ethernet-input
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
02:04:22:554245: l2-input
  l2-input: sw_if_index 7 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29
02:04:22:554253: l2-output
  l2-output: sw_if_index 6 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29 data 08 00 45 00 00 34 cb b6 40 00 40 06
02:04:22:554261: memif3/0-output
  memif3/0 
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
  TCP: 172.55.244.5 -> 172.55.252.1
    tos 0x00, ttl 64, length 52, checksum 0x2697 dscp CS0 ecn NON_ECN
    fragment id 0xcbb6, flags DONT_FRAGMENT
  TCP: 5000 -> 40470
    seq. 0x0867cddb ack 0x2ecebfe5
    flags 0x10 ACK, tcp header: 32 bytes
    window 502, checksum 0x67a9

Packet 1092

02:04:22:555418: memif-input
  memif: hw_if_index 2 next-index 4
    slot: ring 0
02:04:22:555425: ethernet-input
  IP4: 02:fe:7c:39:0d:4a -> 02:fe:af:46:8f:24
02:04:22:555429: l2-input
  l2-input: sw_if_index 2 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a
02:04:22:555431: l2-output
  l2-output: sw_if_index 3 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a data 08 00 45 00 00 34 cb b6 40 00 3f 06
02:04:22:555433: vxlan4-encap
  VXLAN encap to vxlan_tunnel0 vni 2
02:04:22:555435: ip4-rewrite
  tx_sw_if_index 1 dpo-idx 15 : ipv4 via 172.19.0.3 host-eth0: mtu:9000 0242ac1300030242ac1300040800 flow hash: 0x993c6e68
  00000000: 0242ac1300030242ac13000408004500006600000000fd116559ac130004ac13
  00000020: 0003686e12b500520000080000000000020002feaf468f2402fe7c39
02:04:22:555437: host-eth0-output
  host-eth0 
  IP4: 02:42:ac:13:00:04 -> 02:42:ac:13:00:03
  UDP: 172.19.0.4 -> 172.19.0.3
    tos 0x00, ttl 253, length 102, checksum 0x6559 dscp CS0 ecn NON_ECN
    fragment id 0x0000
  UDP: 26734 -> 4789
    length 82, checksum 0x0000

Packet 1093

02:04:22:906634: virtio-input
  virtio: hw_if_index 7 next-index 4 vring 0 len 74
    hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
02:04:22:906643: ethernet-input
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
02:04:22:906655: l2-input
  l2-input: sw_if_index 7 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29
02:04:22:906664: l2-output
  l2-output: sw_if_index 6 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29 data 08 00 45 00 00 3c 19 ec 40 00 40 06
02:04:22:906667: memif3/0-output
  memif3/0 
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
  TCP: 172.55.244.5 -> 172.55.252.1
    tos 0x00, ttl 64, length 60, checksum 0xd859 dscp CS0 ecn NON_ECN
    fragment id 0x19ec, flags DONT_FRAGMENT
  TCP: 47964 -> 5000
    seq. 0xe11757eb ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 64860, checksum 0x3be2

Packet 1094

02:04:22:907761: memif-input
  memif: hw_if_index 2 next-index 4
    slot: ring 0
02:04:22:907764: ethernet-input
  IP4: 02:fe:7c:39:0d:4a -> 02:fe:af:46:8f:24
02:04:22:907767: l2-input
  l2-input: sw_if_index 2 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a
02:04:22:907772: l2-output
  l2-output: sw_if_index 3 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a data 08 00 45 00 00 3c 19 ec 40 00 3f 06
02:04:22:907772: vxlan4-encap
  VXLAN encap to vxlan_tunnel0 vni 2
02:04:22:907774: ip4-rewrite
  tx_sw_if_index 1 dpo-idx 15 : ipv4 via 172.19.0.3 host-eth0: mtu:9000 0242ac1300030242ac1300040800 flow hash: 0xf5fb0d7c
  00000000: 0242ac1300030242ac13000408004500006e00000000fd116551ac130004ac13
  00000020: 00037c0d12b5005a0000080000000000020002feaf468f2402fe7c39
02:04:22:907776: host-eth0-output
  host-eth0 
  IP4: 02:42:ac:13:00:04 -> 02:42:ac:13:00:03
  UDP: 172.19.0.4 -> 172.19.0.3
    tos 0x00, ttl 253, length 110, checksum 0x6551 dscp CS0 ecn NON_ECN
    fragment id 0x0000
  UDP: 31757 -> 4789
    length 90, checksum 0x0000

Packet 1095

02:04:22:913186: memif-input
  memif: hw_if_index 6 next-index 4
    slot: ring 0
02:04:22:913192: ethernet-input
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
02:04:22:913195: l2-input
  l2-input: sw_if_index 6 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4
02:04:22:913197: l2-output
  l2-output: sw_if_index 7 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4 data 08 00 45 00 00 3c 00 00 40 00 3e 06
02:04:22:913197: tap0-output
  tap0 
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
  TCP: 172.55.252.1 -> 172.55.244.5
    tos 0x00, ttl 62, length 60, checksum 0xf445 dscp CS0 ecn NON_ECN
    fragment id 0x0000, flags DONT_FRAGMENT
  TCP: 5000 -> 47964
    seq. 0x35faa4e5 ack 0xe11757ec
    flags 0x12 SYN ACK, tcp header: 40 bytes
    window 64308, checksum 0xd0d0

Packet 1096

02:04:22:914293: virtio-input
  virtio: hw_if_index 7 next-index 4 vring 0 len 66
    hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
02:04:22:914298: ethernet-input
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
02:04:22:914308: l2-input
  l2-input: sw_if_index 7 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29
02:04:22:914315: l2-output
  l2-output: sw_if_index 6 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29 data 08 00 45 00 00 34 19 ed 40 00 40 06
02:04:22:914317: memif3/0-output
  memif3/0 
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
  TCP: 172.55.244.5 -> 172.55.252.1
    tos 0x00, ttl 64, length 52, checksum 0xd860 dscp CS0 ecn NON_ECN
    fragment id 0x19ed, flags DONT_FRAGMENT
  TCP: 47964 -> 5000
    seq. 0xe11757ec ack 0x35faa4e6
    flags 0x10 ACK, tcp header: 32 bytes
    window 507, checksum 0xf89d

Packet 1097

02:04:22:914293: virtio-input
  virtio: hw_if_index 7 next-index 4 vring 0 len 152
    hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
02:04:22:914298: ethernet-input
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
02:04:22:914308: l2-input
  l2-input: sw_if_index 7 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29
02:04:22:914315: l2-output
  l2-output: sw_if_index 6 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29 data 08 00 45 00 00 8a 19 ee 40 00 40 06
02:04:22:914317: memif3/0-output
  memif3/0 
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
  TCP: 172.55.244.5 -> 172.55.252.1
    tos 0x00, ttl 64, length 138, checksum 0xd809 dscp CS0 ecn NON_ECN
    fragment id 0x19ee, flags DONT_FRAGMENT
  TCP: 47964 -> 5000
    seq. 0xe11757ec ack 0x35faa4e6
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 507, checksum 0x1693

Packet 1098

02:04:22:915352: memif-input
  memif: hw_if_index 2 next-index 4
    slot: ring 0
02:04:22:915356: ethernet-input
  IP4: 02:fe:7c:39:0d:4a -> 02:fe:af:46:8f:24
02:04:22:915358: l2-input
  l2-input: sw_if_index 2 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a
02:04:22:915359: l2-output
  l2-output: sw_if_index 3 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a data 08 00 45 00 00 34 19 ed 40 00 3f 06
02:04:22:915360: vxlan4-encap
  VXLAN encap to vxlan_tunnel0 vni 2
02:04:22:915362: ip4-rewrite
  tx_sw_if_index 1 dpo-idx 15 : ipv4 via 172.19.0.3 host-eth0: mtu:9000 0242ac1300030242ac1300040800 flow hash: 0xf5fb0d7c
  00000000: 0242ac1300030242ac13000408004500006600000000fd116559ac130004ac13
  00000020: 00037c0d12b500520000080000000000020002feaf468f2402fe7c39
02:04:22:915364: host-eth0-output
  host-eth0 
  IP4: 02:42:ac:13:00:04 -> 02:42:ac:13:00:03
  UDP: 172.19.0.4 -> 172.19.0.3
    tos 0x00, ttl 253, length 102, checksum 0x6559 dscp CS0 ecn NON_ECN
    fragment id 0x0000
  UDP: 31757 -> 4789
    length 82, checksum 0x0000

Packet 1099

02:04:22:915352: memif-input
  memif: hw_if_index 2 next-index 4
    slot: ring 0
02:04:22:915356: ethernet-input
  IP4: 02:fe:7c:39:0d:4a -> 02:fe:af:46:8f:24
02:04:22:915358: l2-input
  l2-input: sw_if_index 2 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a
02:04:22:915359: l2-output
  l2-output: sw_if_index 3 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a data 08 00 45 00 00 8a 19 ee 40 00 3f 06
02:04:22:915360: vxlan4-encap
  VXLAN encap to vxlan_tunnel0 vni 2
02:04:22:915362: ip4-rewrite
  tx_sw_if_index 1 dpo-idx 15 : ipv4 via 172.19.0.3 host-eth0: mtu:9000 0242ac1300030242ac1300040800 flow hash: 0xf5fb0d7c
  00000000: 0242ac1300030242ac1300040800450000bc00000000fd116503ac130004ac13
  00000020: 00037c0d12b500a80000080000000000020002feaf468f2402fe7c39
02:04:22:915364: host-eth0-output
  host-eth0 
  IP4: 02:42:ac:13:00:04 -> 02:42:ac:13:00:03
  UDP: 172.19.0.4 -> 172.19.0.3
    tos 0x00, ttl 253, length 188, checksum 0x6503 dscp CS0 ecn NON_ECN
    fragment id 0x0000
  UDP: 31757 -> 4789
    length 168, checksum 0x0000

Packet 1100

02:04:22:940730: memif-input
  memif: hw_if_index 6 next-index 4
    slot: ring 0
02:04:22:940735: ethernet-input
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
02:04:22:940739: l2-input
  l2-input: sw_if_index 6 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4
02:04:22:940740: l2-output
  l2-output: sw_if_index 7 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4 data 08 00 45 00 00 34 8c dd 40 00 3e 06
02:04:22:940741: tap0-output
  tap0 
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
  TCP: 172.55.252.1 -> 172.55.244.5
    tos 0x00, ttl 62, length 52, checksum 0x6770 dscp CS0 ecn NON_ECN
    fragment id 0x8cdd, flags DONT_FRAGMENT
  TCP: 5000 -> 47964
    seq. 0x35faa4e6 ack 0xe1175842
    flags 0x10 ACK, tcp header: 32 bytes
    window 502, checksum 0xf844

Packet 1101

02:04:23:041629: memif-input
  memif: hw_if_index 6 next-index 4
    slot: ring 0
02:04:23:041634: ethernet-input
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
02:04:23:041638: l2-input
  l2-input: sw_if_index 6 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4
02:04:23:041640: l2-output
  l2-output: sw_if_index 7 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4 data 08 00 45 00 00 45 8c de 40 00 3e 06
02:04:23:041646: tap0-output
  tap0 
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
  TCP: 172.55.252.1 -> 172.55.244.5
    tos 0x00, ttl 62, length 69, checksum 0x675e dscp CS0 ecn NON_ECN
    fragment id 0x8cde, flags DONT_FRAGMENT
  TCP: 5000 -> 47964
    seq. 0x35faa4e6 ack 0xe1175842
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 502, checksum 0x37ef

Packet 1102

02:04:23:041629: memif-input
  memif: hw_if_index 6 next-index 4
    slot: ring 0
02:04:23:041634: ethernet-input
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
02:04:23:041638: l2-input
  l2-input: sw_if_index 6 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4
02:04:23:041640: l2-output
  l2-output: sw_if_index 7 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4 data 08 00 45 00 00 fb 8c df 40 00 3e 06
02:04:23:041646: tap0-output
  tap0 
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
  TCP: 172.55.252.1 -> 172.55.244.5
    tos 0x00, ttl 62, length 251, checksum 0x66a7 dscp CS0 ecn NON_ECN
    fragment id 0x8cdf, flags DONT_FRAGMENT
  TCP: 5000 -> 47964
    seq. 0x35faa4f7 ack 0xe1175842
    flags 0x19 FIN PSH ACK, tcp header: 32 bytes
    window 502, checksum 0xa286

Packet 1103

02:04:23:042731: virtio-input
  virtio: hw_if_index 7 next-index 4 vring 0 len 66
    hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
02:04:23:042736: ethernet-input
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
02:04:23:042749: l2-input
  l2-input: sw_if_index 7 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29
02:04:23:042760: l2-output
  l2-output: sw_if_index 6 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29 data 08 00 45 00 00 34 19 ef 40 00 40 06
02:04:23:042763: memif3/0-output
  memif3/0 
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
  TCP: 172.55.244.5 -> 172.55.252.1
    tos 0x00, ttl 64, length 52, checksum 0xd85e dscp CS0 ecn NON_ECN
    fragment id 0x19ef, flags DONT_FRAGMENT
  TCP: 47964 -> 5000
    seq. 0xe1175842 ack 0x35faa4f7
    flags 0x10 ACK, tcp header: 32 bytes
    window 507, checksum 0xf736

Packet 1104

02:04:23:042731: virtio-input
  virtio: hw_if_index 7 next-index 4 vring 0 len 66
    hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
02:04:23:042736: ethernet-input
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
02:04:23:042749: l2-input
  l2-input: sw_if_index 7 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29
02:04:23:042760: l2-output
  l2-output: sw_if_index 6 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29 data 08 00 45 00 00 34 19 f0 40 00 40 06
02:04:23:042763: memif3/0-output
  memif3/0 
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
  TCP: 172.55.244.5 -> 172.55.252.1
    tos 0x00, ttl 64, length 52, checksum 0xd85d dscp CS0 ecn NON_ECN
    fragment id 0x19f0, flags DONT_FRAGMENT
  TCP: 47964 -> 5000
    seq. 0xe1175842 ack 0x35faa5bf
    flags 0x11 FIN ACK, tcp header: 32 bytes
    window 506, checksum 0xf66e

Packet 1105

02:04:23:043999: memif-input
  memif: hw_if_index 2 next-index 4
    slot: ring 0
02:04:23:044005: ethernet-input
  IP4: 02:fe:7c:39:0d:4a -> 02:fe:af:46:8f:24
02:04:23:044015: l2-input
  l2-input: sw_if_index 2 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a
02:04:23:044023: l2-output
  l2-output: sw_if_index 3 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a data 08 00 45 00 00 34 19 ef 40 00 3f 06
02:04:23:044025: vxlan4-encap
  VXLAN encap to vxlan_tunnel0 vni 2
02:04:23:044029: ip4-rewrite
  tx_sw_if_index 1 dpo-idx 15 : ipv4 via 172.19.0.3 host-eth0: mtu:9000 0242ac1300030242ac1300040800 flow hash: 0xf5fb0d7c
  00000000: 0242ac1300030242ac13000408004500006600000000fd116559ac130004ac13
  00000020: 00037c0d12b500520000080000000000020002feaf468f2402fe7c39
02:04:23:044031: host-eth0-output
  host-eth0 
  IP4: 02:42:ac:13:00:04 -> 02:42:ac:13:00:03
  UDP: 172.19.0.4 -> 172.19.0.3
    tos 0x00, ttl 253, length 102, checksum 0x6559 dscp CS0 ecn NON_ECN
    fragment id 0x0000
  UDP: 31757 -> 4789
    length 82, checksum 0x0000

Packet 1106

02:04:23:043999: memif-input
  memif: hw_if_index 2 next-index 4
    slot: ring 0
02:04:23:044005: ethernet-input
  IP4: 02:fe:7c:39:0d:4a -> 02:fe:af:46:8f:24
02:04:23:044015: l2-input
  l2-input: sw_if_index 2 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a
02:04:23:044023: l2-output
  l2-output: sw_if_index 3 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a data 08 00 45 00 00 34 19 f0 40 00 3f 06
02:04:23:044025: vxlan4-encap
  VXLAN encap to vxlan_tunnel0 vni 2
02:04:23:044029: ip4-rewrite
  tx_sw_if_index 1 dpo-idx 15 : ipv4 via 172.19.0.3 host-eth0: mtu:9000 0242ac1300030242ac1300040800 flow hash: 0xf5fb0d7c
  00000000: 0242ac1300030242ac13000408004500006600000000fd116559ac130004ac13
  00000020: 00037c0d12b500520000080000000000020002feaf468f2402fe7c39
02:04:23:044031: host-eth0-output
  host-eth0 
  IP4: 02:42:ac:13:00:04 -> 02:42:ac:13:00:03
  UDP: 172.19.0.4 -> 172.19.0.3
    tos 0x00, ttl 253, length 102, checksum 0x6559 dscp CS0 ecn NON_ECN
    fragment id 0x0000
  UDP: 31757 -> 4789
    length 82, checksum 0x0000

Packet 1107

02:04:23:051301: memif-input
  memif: hw_if_index 6 next-index 4
    slot: ring 0
02:04:23:051307: ethernet-input
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
02:04:23:051310: l2-input
  l2-input: sw_if_index 6 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4
02:04:23:051311: l2-output
  l2-output: sw_if_index 7 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4 data 08 00 45 00 00 34 8c e0 40 00 3e 06
02:04:23:051313: tap0-output
  tap0 
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
  TCP: 172.55.252.1 -> 172.55.244.5
    tos 0x00, ttl 62, length 52, checksum 0x676d dscp CS0 ecn NON_ECN
    fragment id 0x8ce0, flags DONT_FRAGMENT
  TCP: 5000 -> 47964
    seq. 0x35faa5bf ack 0xe1175843
    flags 0x10 ACK, tcp header: 32 bytes
    window 502, checksum 0xf668

Packet 1108

02:04:23:245441: virtio-input
  virtio: hw_if_index 7 next-index 4 vring 0 len 74
    hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
02:04:23:245446: ethernet-input
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
02:04:23:245455: l2-input
  l2-input: sw_if_index 7 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29
02:04:23:245463: l2-output
  l2-output: sw_if_index 6 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29 data 08 00 45 00 00 3c 51 f2 40 00 40 06
02:04:23:245466: memif3/0-output
  memif3/0 
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
  TCP: 172.55.244.5 -> 172.55.252.1
    tos 0x00, ttl 64, length 60, checksum 0xa053 dscp CS0 ecn NON_ECN
    fragment id 0x51f2, flags DONT_FRAGMENT
  TCP: 47992 -> 5000
    seq. 0x3c718b93 ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 64860, checksum 0xab72

Packet 1109

02:04:23:246509: memif-input
  memif: hw_if_index 2 next-index 4
    slot: ring 0
02:04:23:246516: ethernet-input
  IP4: 02:fe:7c:39:0d:4a -> 02:fe:af:46:8f:24
02:04:23:246519: l2-input
  l2-input: sw_if_index 2 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a
02:04:23:246520: l2-output
  l2-output: sw_if_index 3 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a data 08 00 45 00 00 3c 51 f2 40 00 3f 06
02:04:23:246521: vxlan4-encap
  VXLAN encap to vxlan_tunnel0 vni 2
02:04:23:246523: ip4-rewrite
  tx_sw_if_index 1 dpo-idx 15 : ipv4 via 172.19.0.3 host-eth0: mtu:9000 0242ac1300030242ac1300040800 flow hash: 0x76e4b5c3
  00000000: 0242ac1300030242ac13000408004500006e00000000fd116551ac130004ac13
  00000020: 0003c3b512b5005a0000080000000000020002feaf468f2402fe7c39
02:04:23:246525: host-eth0-output
  host-eth0 
  IP4: 02:42:ac:13:00:04 -> 02:42:ac:13:00:03
  UDP: 172.19.0.4 -> 172.19.0.3
    tos 0x00, ttl 253, length 110, checksum 0x6551 dscp CS0 ecn NON_ECN
    fragment id 0x0000
  UDP: 50101 -> 4789
    length 90, checksum 0x0000

Packet 1110

02:04:23:251994: memif-input
  memif: hw_if_index 6 next-index 4
    slot: ring 0
02:04:23:251997: ethernet-input
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
02:04:23:251999: l2-input
  l2-input: sw_if_index 6 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4
02:04:23:252000: l2-output
  l2-output: sw_if_index 7 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4 data 08 00 45 00 00 3c 00 00 40 00 3e 06
02:04:23:252001: tap0-output
  tap0 
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
  TCP: 172.55.252.1 -> 172.55.244.5
    tos 0x00, ttl 62, length 60, checksum 0xf445 dscp CS0 ecn NON_ECN
    fragment id 0x0000, flags DONT_FRAGMENT
  TCP: 5000 -> 47992
    seq. 0x361ec92c ack 0x3c718b94
    flags 0x12 SYN ACK, tcp header: 40 bytes
    window 64308, checksum 0x1aa4

Packet 1111

02:04:23:253070: virtio-input
  virtio: hw_if_index 7 next-index 4 vring 0 len 66
    hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
02:04:23:253074: ethernet-input
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
02:04:23:253082: l2-input
  l2-input: sw_if_index 7 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29
02:04:23:253090: l2-output
  l2-output: sw_if_index 6 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29 data 08 00 45 00 00 34 51 f3 40 00 40 06
02:04:23:253091: memif3/0-output
  memif3/0 
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
  TCP: 172.55.244.5 -> 172.55.252.1
    tos 0x00, ttl 64, length 52, checksum 0xa05a dscp CS0 ecn NON_ECN
    fragment id 0x51f3, flags DONT_FRAGMENT
  TCP: 47992 -> 5000
    seq. 0x3c718b94 ack 0x361ec92d
    flags 0x10 ACK, tcp header: 32 bytes
    window 507, checksum 0x4271

Packet 1112

02:04:23:253070: virtio-input
  virtio: hw_if_index 7 next-index 4 vring 0 len 174
    hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
02:04:23:253074: ethernet-input
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
02:04:23:253082: l2-input
  l2-input: sw_if_index 7 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29
02:04:23:253090: l2-output
  l2-output: sw_if_index 6 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29 data 08 00 45 00 00 a0 51 f4 40 00 40 06
02:04:23:253091: memif3/0-output
  memif3/0 
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
  TCP: 172.55.244.5 -> 172.55.252.1
    tos 0x00, ttl 64, length 160, checksum 0x9fed dscp CS0 ecn NON_ECN
    fragment id 0x51f4, flags DONT_FRAGMENT
  TCP: 47992 -> 5000
    seq. 0x3c718b94 ack 0x361ec92d
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 507, checksum 0x9f75

Packet 1113

02:04:23:254179: memif-input
  memif: hw_if_index 2 next-index 4
    slot: ring 0
02:04:23:254184: ethernet-input
  IP4: 02:fe:7c:39:0d:4a -> 02:fe:af:46:8f:24
02:04:23:254186: l2-input
  l2-input: sw_if_index 2 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a
02:04:23:254187: l2-output
  l2-output: sw_if_index 3 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a data 08 00 45 00 00 34 51 f3 40 00 3f 06
02:04:23:254188: vxlan4-encap
  VXLAN encap to vxlan_tunnel0 vni 2
02:04:23:254191: ip4-rewrite
  tx_sw_if_index 1 dpo-idx 15 : ipv4 via 172.19.0.3 host-eth0: mtu:9000 0242ac1300030242ac1300040800 flow hash: 0x76e4b5c3
  00000000: 0242ac1300030242ac13000408004500006600000000fd116559ac130004ac13
  00000020: 0003c3b512b500520000080000000000020002feaf468f2402fe7c39
02:04:23:254193: host-eth0-output
  host-eth0 
  IP4: 02:42:ac:13:00:04 -> 02:42:ac:13:00:03
  UDP: 172.19.0.4 -> 172.19.0.3
    tos 0x00, ttl 253, length 102, checksum 0x6559 dscp CS0 ecn NON_ECN
    fragment id 0x0000
  UDP: 50101 -> 4789
    length 82, checksum 0x0000

Packet 1114

02:04:23:254179: memif-input
  memif: hw_if_index 2 next-index 4
    slot: ring 0
02:04:23:254184: ethernet-input
  IP4: 02:fe:7c:39:0d:4a -> 02:fe:af:46:8f:24
02:04:23:254186: l2-input
  l2-input: sw_if_index 2 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a
02:04:23:254187: l2-output
  l2-output: sw_if_index 3 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a data 08 00 45 00 00 a0 51 f4 40 00 3f 06
02:04:23:254188: vxlan4-encap
  VXLAN encap to vxlan_tunnel0 vni 2
02:04:23:254191: ip4-rewrite
  tx_sw_if_index 1 dpo-idx 15 : ipv4 via 172.19.0.3 host-eth0: mtu:9000 0242ac1300030242ac1300040800 flow hash: 0x76e4b5c3
  00000000: 0242ac1300030242ac1300040800450000d200000000fd1164edac130004ac13
  00000020: 0003c3b512b500be0000080000000000020002feaf468f2402fe7c39
02:04:23:254193: host-eth0-output
  host-eth0 
  IP4: 02:42:ac:13:00:04 -> 02:42:ac:13:00:03
  UDP: 172.19.0.4 -> 172.19.0.3
    tos 0x00, ttl 253, length 210, checksum 0x64ed dscp CS0 ecn NON_ECN
    fragment id 0x0000
  UDP: 50101 -> 4789
    length 190, checksum 0x0000

Packet 1115

02:04:23:284994: memif-input
  memif: hw_if_index 6 next-index 4
    slot: ring 0
02:04:23:284999: ethernet-input
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
02:04:23:285003: l2-input
  l2-input: sw_if_index 6 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4
02:04:23:285004: l2-output
  l2-output: sw_if_index 7 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4 data 08 00 45 00 00 34 4c f5 40 00 3e 06
02:04:23:285005: tap0-output
  tap0 
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
  TCP: 172.55.252.1 -> 172.55.244.5
    tos 0x00, ttl 62, length 52, checksum 0xa758 dscp CS0 ecn NON_ECN
    fragment id 0x4cf5, flags DONT_FRAGMENT
  TCP: 5000 -> 47992
    seq. 0x361ec92d ack 0x3c718c00
    flags 0x10 ACK, tcp header: 32 bytes
    window 502, checksum 0x4202

Packet 1116

02:04:23:420938: memif-input
  memif: hw_if_index 6 next-index 4
    slot: ring 0
02:04:23:420945: ethernet-input
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
02:04:23:420950: l2-input
  l2-input: sw_if_index 6 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4
02:04:23:420953: l2-output
  l2-output: sw_if_index 7 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4 data 08 00 45 00 00 45 4c f6 40 00 3e 06
02:04:23:420955: tap0-output
  tap0 
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
  TCP: 172.55.252.1 -> 172.55.244.5
    tos 0x00, ttl 62, length 69, checksum 0xa746 dscp CS0 ecn NON_ECN
    fragment id 0x4cf6, flags DONT_FRAGMENT
  TCP: 5000 -> 47992
    seq. 0x361ec92d ack 0x3c718c00
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 502, checksum 0x8193

Packet 1117

02:04:23:420938: memif-input
  memif: hw_if_index 6 next-index 4
    slot: ring 0
02:04:23:420945: ethernet-input
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
02:04:23:420950: l2-input
  l2-input: sw_if_index 6 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4
02:04:23:420953: l2-output
  l2-output: sw_if_index 7 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4 data 08 00 45 00 00 fb 4c f7 40 00 3e 06
02:04:23:420955: tap0-output
  tap0 
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
  TCP: 172.55.252.1 -> 172.55.244.5
    tos 0x00, ttl 62, length 251, checksum 0xa68f dscp CS0 ecn NON_ECN
    fragment id 0x4cf7, flags DONT_FRAGMENT
  TCP: 5000 -> 47992
    seq. 0x361ec93e ack 0x3c718c00
    flags 0x19 FIN PSH ACK, tcp header: 32 bytes
    window 502, checksum 0xec29

Packet 1118

02:04:23:423674: virtio-input
  virtio: hw_if_index 7 next-index 4 vring 0 len 66
    hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
02:04:23:423680: ethernet-input
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
02:04:23:423712: l2-input
  l2-input: sw_if_index 7 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29
02:04:23:423750: l2-output
  l2-output: sw_if_index 6 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29 data 08 00 45 00 00 34 51 f5 40 00 40 06
02:04:23:423763: memif3/0-output
  memif3/0 
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
  TCP: 172.55.244.5 -> 172.55.252.1
    tos 0x00, ttl 64, length 52, checksum 0xa058 dscp CS0 ecn NON_ECN
    fragment id 0x51f5, flags DONT_FRAGMENT
  TCP: 47992 -> 5000
    seq. 0x3c718c00 ack 0x361ec93e
    flags 0x10 ACK, tcp header: 32 bytes
    window 507, checksum 0x40b2

Packet 1119

02:04:23:423674: virtio-input
  virtio: hw_if_index 7 next-index 4 vring 0 len 66
    hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
02:04:23:423680: ethernet-input
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
02:04:23:423712: l2-input
  l2-input: sw_if_index 7 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29
02:04:23:423750: l2-output
  l2-output: sw_if_index 6 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29 data 08 00 45 00 00 34 51 f6 40 00 40 06
02:04:23:423763: memif3/0-output
  memif3/0 
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
  TCP: 172.55.244.5 -> 172.55.252.1
    tos 0x00, ttl 64, length 52, checksum 0xa057 dscp CS0 ecn NON_ECN
    fragment id 0x51f6, flags DONT_FRAGMENT
  TCP: 47992 -> 5000
    seq. 0x3c718c00 ack 0x361eca06
    flags 0x11 FIN ACK, tcp header: 32 bytes
    window 506, checksum 0x3fe8

Packet 1120

02:04:23:424883: memif-input
  memif: hw_if_index 2 next-index 4
    slot: ring 0
02:04:23:424898: ethernet-input
  IP4: 02:fe:7c:39:0d:4a -> 02:fe:af:46:8f:24
02:04:23:424908: l2-input
  l2-input: sw_if_index 2 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a
02:04:23:424920: l2-output
  l2-output: sw_if_index 3 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a data 08 00 45 00 00 34 51 f5 40 00 3f 06
02:04:23:424934: vxlan4-encap
  VXLAN encap to vxlan_tunnel0 vni 2
02:04:23:424948: ip4-rewrite
  tx_sw_if_index 1 dpo-idx 15 : ipv4 via 172.19.0.3 host-eth0: mtu:9000 0242ac1300030242ac1300040800 flow hash: 0x76e4b5c3
  00000000: 0242ac1300030242ac13000408004500006600000000fd116559ac130004ac13
  00000020: 0003c3b512b500520000080000000000020002feaf468f2402fe7c39
02:04:23:424950: host-eth0-output
  host-eth0 
  IP4: 02:42:ac:13:00:04 -> 02:42:ac:13:00:03
  UDP: 172.19.0.4 -> 172.19.0.3
    tos 0x00, ttl 253, length 102, checksum 0x6559 dscp CS0 ecn NON_ECN
    fragment id 0x0000
  UDP: 50101 -> 4789
    length 82, checksum 0x0000

Packet 1121

02:04:23:424883: memif-input
  memif: hw_if_index 2 next-index 4
    slot: ring 0
02:04:23:424898: ethernet-input
  IP4: 02:fe:7c:39:0d:4a -> 02:fe:af:46:8f:24
02:04:23:424908: l2-input
  l2-input: sw_if_index 2 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a
02:04:23:424920: l2-output
  l2-output: sw_if_index 3 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a data 08 00 45 00 00 34 51 f6 40 00 3f 06
02:04:23:424934: vxlan4-encap
  VXLAN encap to vxlan_tunnel0 vni 2
02:04:23:424948: ip4-rewrite
  tx_sw_if_index 1 dpo-idx 15 : ipv4 via 172.19.0.3 host-eth0: mtu:9000 0242ac1300030242ac1300040800 flow hash: 0x76e4b5c3
  00000000: 0242ac1300030242ac13000408004500006600000000fd116559ac130004ac13
  00000020: 0003c3b512b500520000080000000000020002feaf468f2402fe7c39
02:04:23:424950: host-eth0-output
  host-eth0 
  IP4: 02:42:ac:13:00:04 -> 02:42:ac:13:00:03
  UDP: 172.19.0.4 -> 172.19.0.3
    tos 0x00, ttl 253, length 102, checksum 0x6559 dscp CS0 ecn NON_ECN
    fragment id 0x0000
  UDP: 50101 -> 4789
    length 82, checksum 0x0000

Packet 1122

02:04:23:435945: memif-input
  memif: hw_if_index 6 next-index 4
    slot: ring 0
02:04:23:435951: ethernet-input
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
02:04:23:435954: l2-input
  l2-input: sw_if_index 6 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4
02:04:23:435956: l2-output
  l2-output: sw_if_index 7 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4 data 08 00 45 00 00 fb 4c f8 40 00 3e 06
02:04:23:435957: tap0-output
  tap0 
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
  TCP: 172.55.252.1 -> 172.55.244.5
    tos 0x00, ttl 62, length 251, checksum 0xa68e dscp CS0 ecn NON_ECN
    fragment id 0x4cf8, flags DONT_FRAGMENT
  TCP: 5000 -> 47992
    seq. 0x361ec93e ack 0x3c718c00
    flags 0x19 FIN PSH ACK, tcp header: 32 bytes
    window 502, checksum 0xec11

Packet 1123

02:04:23:435945: memif-input
  memif: hw_if_index 6 next-index 4
    slot: ring 0
02:04:23:435951: ethernet-input
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
02:04:23:435954: l2-input
  l2-input: sw_if_index 6 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4
02:04:23:435956: l2-output
  l2-output: sw_if_index 7 dst 02:fe:e3:96:41:29 src 02:fe:09:5a:c0:e4 data 08 00 45 00 00 34 4c f9 40 00 3e 06
02:04:23:435957: tap0-output
  tap0 
  IP4: 02:fe:09:5a:c0:e4 -> 02:fe:e3:96:41:29
  TCP: 172.55.252.1 -> 172.55.244.5
    tos 0x00, ttl 62, length 52, checksum 0xa754 dscp CS0 ecn NON_ECN
    fragment id 0x4cf9, flags DONT_FRAGMENT
  TCP: 5000 -> 47992
    seq. 0x361eca06 ack 0x3c718c01
    flags 0x10 ACK, tcp header: 32 bytes
    window 502, checksum 0x3fd0

Packet 1124

02:04:23:437960: virtio-input
  virtio: hw_if_index 7 next-index 4 vring 0 len 78
    hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
02:04:23:437970: ethernet-input
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
02:04:23:437975: l2-input
  l2-input: sw_if_index 7 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29
02:04:23:437978: l2-output
  l2-output: sw_if_index 6 dst 02:fe:09:5a:c0:e4 src 02:fe:e3:96:41:29 data 08 00 45 00 00 40 51 f7 40 00 40 06
02:04:23:437980: memif3/0-output
  memif3/0 
  IP4: 02:fe:e3:96:41:29 -> 02:fe:09:5a:c0:e4
  TCP: 172.55.244.5 -> 172.55.252.1
    tos 0x00, ttl 64, length 64, checksum 0xa04a dscp CS0 ecn NON_ECN
    fragment id 0x51f7, flags DONT_FRAGMENT
  TCP: 47992 -> 5000
    seq. 0x3c718c01 ack 0x361eca06
    flags 0x10 ACK, tcp header: 44 bytes
    window 506, checksum 0x0a29

Packet 1125

02:04:23:439100: memif-input
  memif: hw_if_index 2 next-index 4
    slot: ring 0
02:04:23:439107: ethernet-input
  IP4: 02:fe:7c:39:0d:4a -> 02:fe:af:46:8f:24
02:04:23:439109: l2-input
  l2-input: sw_if_index 2 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a
02:04:23:439111: l2-output
  l2-output: sw_if_index 3 dst 02:fe:af:46:8f:24 src 02:fe:7c:39:0d:4a data 08 00 45 00 00 40 51 f7 40 00 3f 06
02:04:23:439112: vxlan4-encap
  VXLAN encap to vxlan_tunnel0 vni 2
02:04:23:439115: ip4-rewrite
  tx_sw_if_index 1 dpo-idx 15 : ipv4 via 172.19.0.3 host-eth0: mtu:9000 0242ac1300030242ac1300040800 flow hash: 0x76e4b5c3
  00000000: 0242ac1300030242ac13000408004500007200000000fd11654dac130004ac13
  00000020: 0003c3b512b5005e0000080000000000020002feaf468f2402fe7c39
02:04:23:439116: host-eth0-output
  host-eth0 
  IP4: 02:42:ac:13:00:04 -> 02:42:ac:13:00:03
  UDP: 172.19.0.4 -> 172.19.0.3
    tos 0x00, ttl 253, length 114, checksum 0x654d dscp CS0 ecn NON_ECN
    fragment id 0x0000
  UDP: 50101 -> 4789
    length 94, checksum 0x0000`,
			want: &Traces{Packets: []Packet{
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
			}},
			wantErr: false,
		},
		{
			name:    "empty",
			data:    ``,
			want:    &Traces{},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseTrace(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseTrace() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseTrace() got = %#v, want %v", got, tt.want)
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

func TestFileTrace(t *testing.T) {
	data, err := ioutil.ReadFile("/tmp/vpptrace_0_-982623859")
	if err != nil {
		panic(err)
	}
	traceData := strings.ReplaceAll(string(data), "\r\n", "\n")
	trac, err := ParseTrace(traceData)
	if err != nil {
		t.Fatalf("ParseTrace() error = %v", err)
	}
	t.Logf("trace: %+v", trac)
}
