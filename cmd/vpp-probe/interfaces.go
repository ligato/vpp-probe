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

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"git.fd.io/govpp.git"
	"git.fd.io/govpp.git/adapter"
	govppapi "git.fd.io/govpp.git/api"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/binapi/vpp2005/interface_types"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/binapi/vpp2005/interfaces"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/binapi/vpp2005/ip"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/binapi/vpp2005/ip_types"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/binapi/vpp2005/vpe"
)

func init() {
	rootCmd.AddCommand(intCmd)
}

var intCmd = &cobra.Command{
	Use:     "interfaces",
	Aliases: []string{"int", "if", "iface"},
	Short:   "List interfaces",
	Run: func(cmd *cobra.Command, args []string) {
		listInterfaces()
	},
}

func listInterfaces() {
	conn, err := govpp.Connect(adapter.DefaultBinapiSocket)
	if err != nil {
		logrus.Fatalln("ERROR: connecting to VPP:", err)
	}
	defer conn.Disconnect()

	ch, err := conn.NewAPIChannel()
	if err != nil {
		logrus.Fatalln("ERROR: creating channel:", err)
	}
	defer conn.Disconnect()

	var msgs []govppapi.Message
	msgs = append(msgs, vpe.AllMessages()...)
	msgs = append(msgs, ip.AllMessages()...)
	msgs = append(msgs, interfaces.AllMessages()...)
	if err := ch.CheckCompatiblity(msgs...); err != nil {
		logrus.Fatal("ERROR: binapi not compatible:", err)
	}

	list := dumpInterfaces(ch)

	printInterfaceTable(os.Stdout, list)
}

type Interface struct {
	Index   uint32
	Name    string
	Tag     string
	State   string
	MTU     MTU
	Type    string
	DevType string
	Link    string
	VRF     uint32
	IPs     []string
}

func printInterfaceTable(out io.Writer, ifaces []*Interface) {
	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 8, 1, '\t', tabwriter.DiscardEmptyColumns)
	fmt.Fprintf(w, "INTERFACE\tIDX\tTYPE\tSTATE\tIP\tVRF\tMTU (l3/ip4/ip6/mpls/link)\t\n")
	for _, iface := range ifaces {
		name := iface.Name
		if len(iface.Tag) > 0 {
			name = fmt.Sprintf("%s (%s)", iface.Name, iface.Tag)
		}
		typ := fmt.Sprintf("%s (%s)", iface.DevType, iface.Type)
		ips := strings.Join(iface.IPs, ", ")
		fmt.Fprintf(w, "%v\t%v\t%v\t%v\v%v\t%v\t%v\t\n",
			name, iface.Index, typ, iface.State, ips, iface.VRF, iface.MTU)
	}
	if err := w.Flush(); err != nil {
		panic(err)
	}
	fmt.Fprint(out, buf.String())
}

func dumpInterfaces(ch govppapi.Channel) []*Interface {
	rpc := interfaces.NewServiceClient(ch)
	stream, err := rpc.DumpSwInterface(context.Background(), &interfaces.SwInterfaceDump{})
	if err != nil {
		logrus.Fatalln("DumpSwInterface failed:", err)
	}
	logrus.Debug("Dumping interfaces")
	var list []*Interface
	for {
		iface, err := stream.Recv()
		if err == io.EOF {
			break
		} else if err != nil {
			logrus.Fatalln("DumpSwInterface failed:", err)
		}
		logrus.Debugf("- interface: %s\n", strings.Trim(iface.InterfaceName, "\x00"))
		list = append(list, &Interface{
			Index:   uint32(iface.SwIfIndex),
			Name:    strings.Trim(iface.InterfaceName, "\x00"),
			Tag:     strings.Trim(iface.Tag, "\x00"),
			MTU:     ifaceMTUs(iface.Mtu, iface.LinkMtu),
			Type:    ifaceTypeToString(iface.Type),
			DevType: iface.InterfaceDevType,
			State:   ifaceFlagsToState(iface.Flags),
		})
	}
	for _, iface := range list {
		iface.VRF = getInterfaceVRF(ch, iface.Index, false)
		iface.IPs = getInterfaceIPs(ch, iface.Index, false)
	}
	return list
}

func getInterfaceVRF(conn govppapi.Channel, idx uint32, ipv6 bool) uint32 {
	rpc := interfaces.NewServiceClient(conn)
	reply, err := rpc.SwInterfaceGetTable(context.Background(), &interfaces.SwInterfaceGetTable{
		SwIfIndex: interface_types.InterfaceIndex(idx),
		IsIPv6:    ipv6,
	})
	if err != nil {
		logrus.Errorf("getting VRF (idx %v) failed: %v", idx, err)
		return 0
	} else if e := govppapi.RetvalToVPPApiError(reply.Retval); e != nil {
		logrus.Errorf("getting VRF (idx %v) failed: %v", idx, err)
		return 0
	}
	return reply.VrfID
}

func getInterfaceIPs(conn govppapi.Channel, idx uint32, ipv6 bool) []string {
	rpc := ip.NewServiceClient(conn)
	stream, err := rpc.DumpIPAddress(context.Background(), &ip.IPAddressDump{
		SwIfIndex: interface_types.InterfaceIndex(idx),
		IsIPv6:    ipv6,
	})
	if err != nil {
		logrus.Fatalln("IPAddressDump failed:", err)
		return nil
	}
	var ips []string
	for {
		ipaddr, err := stream.Recv()
		if err == io.EOF {
			break
		} else if err != nil {
			logrus.Fatalln("IPAddressDump failed:", err)
		}
		ips = append(ips, PrefixString(ipaddr.Prefix))
	}
	return ips
}

func PrefixString(x ip_types.AddressWithPrefix) string {
	addr := AddressString(x.Address)
	return addr + "/" + strconv.Itoa(int(x.Len))
}

func AddressToIP(x ip_types.Address) net.IP {
	if x.Af == ip_types.ADDRESS_IP6 {
		ip6 := x.Un.GetIP6()
		return net.IP(ip6[:]).To16()
	} else {
		ip4 := x.Un.GetIP4()
		return net.IP(ip4[:]).To4()
	}
}
func AddressString(x ip_types.Address) string {
	return AddressToIP(x).String()
}

type MTU struct {
	L3       uint
	IP4, IP6 uint
	MPLS     uint
	Link     uint
}

func (mtu MTU) String() string {
	return fmt.Sprintf("%d/%d/%d/%d/%d", mtu.L3, mtu.IP4, mtu.IP6, mtu.MPLS, mtu.Link)
}

func ifaceMTUs(mtu []uint32, linkMtu uint16) MTU {
	return MTU{
		L3:   uint(mtu[0]),
		IP4:  uint(mtu[1]),
		IP6:  uint(mtu[2]),
		MPLS: uint(mtu[3]),
		Link: uint(linkMtu),
	}
}

func ifaceTypeToString(ifType interface_types.IfType) string {
	typ := strings.TrimPrefix(ifType.String(), "IF_API_TYPE_")
	return strings.ToLower(typ)
}

func ifaceFlagsToState(flags interface_types.IfStatusFlags) string {
	switch flags {
	case 3:
		return "up"
	case 2:
		return "up (admin down)"
	case 1:
		return "up (link down)"
	case 0:
		return "down"
	default:
		return fmt.Sprint(flags)
	}
}

/*type InterfaceEvent struct {
}

func watchIfaceEvents(conn api.Connection) <-chan *interfaces.SwInterfaceEvent {
	rpc := interfaces.NewServiceClient(conn)
	reply, err := rpc.WantInterfaceEvents(context.Background(), &interfaces.WantInterfaceEvents{
		EnableDisable: 1,
		PID:           uint32(pid),
	})
	if err != nil {
		logrus.Errorf("getting VRF (idx %v) failed: %v", idx, err)
		return 0
	} else if e := api.RetvalToVPPApiError(reply.Retval); e != nil {
		logrus.Errorf("getting VRF (idx %v) failed: %v", idx, err)
		return 0
	}
	return reply.VrfID
}*/

var NotifChanBufferSize = 10

func WatchInterfaceEvents(ctx context.Context, conn govppapi.ChannelProvider, eventsCh chan<- *interfaces.SwInterfaceEvent) error {
	ch, err := conn.NewAPIChannel()
	if err != nil {
		return fmt.Errorf("creating channel failed: %v", err)
	}
	defer ch.Close()

	rpc := interfaces.NewServiceClient(ch)

	notifChan := make(chan govppapi.Message, NotifChanBufferSize)

	// subscribe to SwInterfaceEvent notifications
	sub, err := ch.SubscribeNotification(notifChan, &interfaces.SwInterfaceEvent{})
	if err != nil {
		return fmt.Errorf("subscribing to VPP notification (sw_interface_event) failed: %v", err)
	}
	unsub := func() {
		if err := sub.Unsubscribe(); err != nil {
			logrus.Warnf("unsubscribing VPP notification (sw_interface_event) failed: %v", err)
		}
	}

	go func() {
		logrus.Debugf("start watching interface events")
		defer logrus.Debugf("done watching interface events (%v)", ctx.Err())

		for {
			select {
			case e, open := <-notifChan:
				if !open {
					logrus.Debugf("interface events channel was closed")
					unsub()
					return
				}
				ifEvent, ok := e.(*interfaces.SwInterfaceEvent)
				if !ok {
					logrus.Debugf("unexpected notification type: %#v", ifEvent)
					continue
				}
				eventsCh <- ifEvent

			case <-ctx.Done():
				unsub()
				return
			}
		}
	}()

	// enable interface events from VPP
	if _, err := rpc.WantInterfaceEvents(ctx, &interfaces.WantInterfaceEvents{
		PID:           uint32(os.Getpid()),
		EnableDisable: 1,
	}); err != nil {
		if errors.Is(err, govppapi.VPPApiError(govppapi.INVALID_REGISTRATION)) {
			logrus.Warnf("already subscribed to interface events: %v", err)
			return nil
		}
		return fmt.Errorf("failed to watch interface events: %v", err)
	}

	return nil
}
