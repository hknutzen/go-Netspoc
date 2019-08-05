package pass1

import (
	"net"
)

func getHostMask(ip net.IP) net.IPMask {
	if len(ip) == 4 {
		return net.CIDRMask(32, 32)
	}
	return net.CIDRMask(128, 128)
}

var zeroIP = net.ParseIP("0.0.0.0")
var zeroIPv6 = net.ParseIP("::")

func getZeroIp(ipv6 bool) net.IP {
	if ipv6 {
		return zeroIPv6
	} else {
		return zeroIP
	}
}

func getNatNetwork(network *Network, natSet natSet) *Network {
	for tag, natNet := range network.nat {
		if (*natSet)[tag] {
			return natNet
		}
	}
	return network
}

func (obj *Network) address (nn natSet) net.IPNet {
	network := getNatNetwork(obj, nn)
	return net.IPNet{IP: network.IP, Mask: network.Mask}
}

func (obj *Subnet) address (nn natSet) net.IPNet {
	network := getNatNetwork(obj.Network, nn)
	return natAddress(obj.IP, obj.Mask, obj.nat, network)
}

func (obj *Interface) address (nn natSet) net.IPNet {
	network := getNatNetwork(obj.Network, nn)
	if obj.negotiated {
		return net.IPNet{IP: network.IP, Mask: network.Mask}
	}
	return natAddress(obj.IP, getHostMask(obj.IP), obj.nat, network)
}

func natAddress (ip net.IP, mask net.IPMask, nat map[string]net.IP, network *Network) net.IPNet {
	if network.dynamic {
		natTag := network.natTag
		if ip, ok := nat[natTag]; ok {

			// Single static NAT IP for this interface.
			return net.IPNet{IP: ip, Mask: getHostMask(ip) }
		} else {
			return net.IPNet{IP: network.IP, Mask: network.Mask}
		}
	}

	// Take higher bits from network NAT, lower bits from original IP.
	// This works with and without NAT.
	n := len(network.IP)
	natIP := make(net.IP, n)
	for i := 0; i < n; i++ {
		natIP[i] = network.IP[i] | ip[i] & ^network.Mask[i]
	}
	return net.IPNet{IP: natIP, Mask: mask }
}
