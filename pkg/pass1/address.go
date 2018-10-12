package pass1

import (
	"net"
)

func getNatNetwork(network *Network, noNatSet noNatSet) *Network {
	if network.nat != nil && noNatSet != nil {
		for tag, natNet := range network.nat {
			if (*noNatSet)[tag] {
				continue
			}
			return natNet
		}
	}
	return network
}

func getHostMask(ip net.IP) net.IPMask {
	if len(ip) == 4 {
		return net.CIDRMask(32, 32)
	}
	return net.CIDRMask(128, 128)
}

func (obj *Network) address (nn noNatSet) net.IPNet {
	network := getNatNetwork(obj, nn)
	return net.IPNet{IP: network.IP, Mask: network.Mask}
}

func (obj *Subnet) address (nn noNatSet) net.IPNet {
	network := getNatNetwork(obj.Network, nn)
	if network.dynamic {
		natTag := network.natTag
		if ip, ok := obj.nat[natTag]; ok {
			
			// Single static NAT IP for this host.
			return net.IPNet{IP: ip, Mask: getHostMask(ip) }
		} else {
			return net.IPNet{IP: network.IP, Mask: network.Mask}
		}
	} else {
		
		// Take higher bits from network NAT, lower bits from original IP.
		// This works with and without NAT.
		n := len(network.IP)
		ip := make(net.IP, n)
		for i := 0; i < n; i++ {
			ip[i] = network.IP[i] | obj.IP[i] & ^network.Mask[i]
		}
		return net.IPNet{IP: ip, Mask: obj.Mask}
	}
}

func (obj *Interface) address (nn noNatSet) net.IPNet {
	network := getNatNetwork(obj.Network, nn)
	if obj.negotiated {
		return net.IPNet{IP: network.IP, Mask: network.Mask}
	} else if network.dynamic {
		natTag := network.natTag
		if ip, ok := obj.nat[natTag]; ok {
				
			// Single static NAT IP for this interface.
			return net.IPNet{IP: ip, Mask: getHostMask(ip) }
		} else {
			return net.IPNet{IP: network.IP, Mask: network.Mask}
		}
	} else {
		
		// Take higher bits from network NAT, lower bits from original IP.
		// This works with and without NAT.
		n := len(network.IP)
		ip := make(net.IP, n)
		for i := 0; i < n; i++ {
			ip[i] = network.IP[i] | obj.IP[i] & ^network.Mask[i]
		}
		return net.IPNet{IP: ip, Mask: getHostMask(ip) }
	}
}
