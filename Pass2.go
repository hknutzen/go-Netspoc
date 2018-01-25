package main

/*
Pass 2 of Netspoc - A Network Security Policy Compiler

(C) 2018 by Heinz Knutzen <heinz.knutzen@googlemail.com>

http://hknutzen.github.com/Netspoc

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

*/

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/mailru/easyjson"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	//	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type Config struct {
	concurrent int
	pipe       bool
	verbose    bool
}

var (
	show_diag = false
	config    = Config{
		concurrent: 8,
		pipe:       false,
		verbose:    false,
	}
)

func to_stderr(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format, args...)
	fmt.Fprintln(os.Stderr)
}

func fatal_err(format string, args ...interface{}) {
	string := "Error: " + fmt.Sprintf(format, args...)
	fmt.Fprintln(os.Stderr, string)
	os.Exit(1)
}

func info(format string, args ...interface{}) {
	if config.verbose {
		string := fmt.Sprintf(format, args...)
		fmt.Fprintln(os.Stderr, string)
	}
}

func diag_msg(msg string) {
	if os.Getenv("SHOW_DIAG") != "" {
		fmt.Fprintln(os.Stderr, "DIAG: "+msg)
	}
}

type IP_Net struct {
	*net.IPNet
	opt_networks                *IP_Net
	no_opt_addrs, need_protect  bool
	name                        string
	up                          *IP_Net
	is_supernet_of_need_protect map[*IP_Net]bool
}
type Proto struct {
	proto        string
	ports        [2]int
	established  bool
	type_, code  int
	name         string
	up           *Proto
	has_neighbor bool
}
type Name2IP_Net map[string]*IP_Net
type Name2Proto map[string]*Proto

func create_ip_obj(ip_net string) *IP_Net {
	_, net, _ := net.ParseCIDR(ip_net)
	return &IP_Net{IPNet: net, name: ip_net}
}

func get_ip_obj(ip net.IP, mask net.IPMask, ip_net2obj Name2IP_Net) *IP_Net {
	prefix, _ := mask.Size()
	name := fmt.Sprintf("%s/%d", ip.String(), prefix)
	obj, ok := ip_net2obj[name]
	if !ok {
		obj = &IP_Net{IPNet: &net.IPNet{IP: ip, Mask: mask}, name: name}
		ip_net2obj[name] = obj
	}
	return obj
}

func create_prt_obj(descr string) *Proto {
	splice := strings.Split(descr, " ")
	proto := splice[0]
	prt := Proto{proto: proto, name: descr}

	switch proto {
	case "tcp", "udp":
		p1, _ := strconv.Atoi(splice[1])
		p2, _ := strconv.Atoi(splice[2])
		prt.ports = [2]int{p1, p2}
		if len(splice) > 3 {
			prt.established = true
		}
	case "icmp":
		if len(splice) > 1 {
			prt.type_, _ = strconv.Atoi(splice[1])
			if len(splice) > 2 {
				prt.code, _ = strconv.Atoi(splice[2])
			} else {
				prt.code = -1
			}
		} else {
			prt.type_ = -1
		}
	}
	return &prt
}

func get_net00_addr(ipv6 bool) string {
	var result string
	if ipv6 {
		result = "::/0"
	} else {
		result = "0.0.0.0/0"
	}
	return result
}

func setup_ip_net_relation(ip_net2obj Name2IP_Net, ipv6 bool) {
	net00 := get_net00_addr(ipv6)
	if _, ok := ip_net2obj[net00]; !ok {
		ip_net2obj[net00] = create_ip_obj(net00)
	}
	mask_ip_hash := make(map[string]map[string]*IP_Net)

	// Collect networks into mask_ip_hash.
	for _, network := range ip_net2obj {
		ip, mask := network.IP, network.Mask
		ip_map, ok := mask_ip_hash[string(mask)]
		if !ok {
			ip_map = make(map[string]*IP_Net)
			mask_ip_hash[string(mask)] = ip_map
		}
		ip_map[string(ip)] = network
	}

	// Compare networks.
	// Go from smaller to larger networks.
	var mask_list []net.IPMask
	for k := range mask_ip_hash {
		mask_list = append(mask_list, net.IPMask(k))
	}
	less := func (i, j int) bool {
		return bytes.Compare(mask_list[i], mask_list[j]) == -1
	}
	sort.Slice(mask_list, func(i, j int) bool { return less(j, i) })
	for i, mask := range mask_list {
		upper_masks := mask_list[i+1:]

		// No supernets available
		if len(upper_masks) == 0 {
			break
		}

		ip_hash := mask_ip_hash[string(mask)]
		for ip, subnet := range ip_hash {

			// Find networks which include current subnet.
			// upper_masks holds masks of potential supernets.
			for _, m := range upper_masks {

				i := net.IP(ip).Mask(net.IPMask(m))
				bignet, ok := mask_ip_hash[string(m)][string(i)]
				if ok {
					subnet.up = bignet
					break
				}
			}
		}
	}

	// Propagate content of attribute opt_networks to all subnets.
	// Go from large to smaller networks.
	sort.Slice(mask_list, less)
	for _, mask := range mask_list {
		for _, network := range mask_ip_hash[string(mask)] {
			up := network.up
			if up == nil {
				continue
			}
			if opt_networks := up.opt_networks; opt_networks != nil {
				network.opt_networks = opt_networks
			}
		}
	}
}

func mark_supernets_of_need_protect(need_protect []*IP_Net) {
	for _, intf := range need_protect {
		up := intf.up
		for up != nil {
			if up.is_supernet_of_need_protect == nil {
				up.is_supernet_of_need_protect = make(map[*IP_Net]bool)
			}
			up.is_supernet_of_need_protect[intf] = true
			up = up.up
		}
	}
}

// Needed for model=Linux.
func add_tcp_udp_icmp(prt2obj Name2Proto) {
	_ = prt("tcp 1 65535", prt2obj)
	_ = prt("udp 1 65535", prt2obj)
	_ = prt("icmp", prt2obj)
}

// Set {up} relation from port range to the smallest port range which
// includes it.
// If no including range is found, link it with next larger protocol.
// Set attribute {has_neighbor} to range adjacent to upper port.
// Abort on overlapping ranges.
func order_ranges(proto string, prt2obj Name2Proto, up *Proto) {
	var ranges []*Proto
	for _, v := range prt2obj {
		if v.proto == proto && !v.established {
			ranges = append(ranges, v)
		}
	}

	// Sort by low port. If low ports are equal, sort reverse by high port.
	// I.e. larger ranges coming first, if there are multiple ranges
	// with identical low port.
	sort.Slice(ranges, func(i, j int) bool {
		return ranges[i].ports[0] < ranges[j].ports[0] ||
			ranges[i].ports[0] == ranges[j].ports[0] &&
				ranges[i].ports[1] > ranges[j].ports[1]
	})

	// Check current range [a1, a2] for sub-ranges, starting at position $i.
	// Set attributes {up} and {has_neighbor}.
	// Return position of range which isn't sub-range or undef
	// if end of array is reached.
	var check_subrange func(a *Proto, a1, a2, i int) int
	check_subrange = func(a *Proto, a1, a2, i int) int {
		for {
			if i == len(ranges) {
				return 0
			}
			b := ranges[i]
			ports := b.ports
			b1, b2 := ports[0], ports[1]

			// Neighbors
			// aaaabbbb
			if a2+1 == b1 {

				// Mark protocol as candidate for joining of port ranges during
				// optimization.
				a.has_neighbor = true
				b.has_neighbor = true

				// Mark other ranges having identical start port.
				for _, c := range ranges[i+1:] {
					if c.ports[0] != b1 {
						break
					}
					c.has_neighbor = true
				}
			}

			// Not related.
			// aaaa    bbbbb
			if a2 < b1 {
				return i
			}

			// a includes b.
			// aaaaaaa
			//  bbbbb
			if a2 >= b2 {
				b.up = a
				i = check_subrange(b, b1, b2, i+1)

				// Stop at end of array.
				if i == 0 {
					return 0
				}
				continue
			}

			// a and b are overlapping.
			// aaaaa
			//   bbbbbb
			// uncoverable statement
			fatal_err(
				"Unexpected overlapping ranges [%d-%d] [%d-%d]",
				a1, a2, b1, b2)
		}
	}

	if len(ranges) == 0 {
		return
	}
	index := 0
	for {
		a := ranges[index]
		a.up = up
		ports := a.ports
		a1, a2 := ports[0], ports[1]
		index = check_subrange(a, a1, a2, index+1)
		if index == 0 {
			return
		}
	}
}

func setup_prt_relation(prt2obj Name2Proto) {
	prt_ip := prt("ip", prt2obj)
	icmp_up, ok := prt2obj["icmp"]
	if !ok {
		icmp_up = prt_ip
	}

	for _, prt := range prt2obj {
		proto := prt.proto
		if proto == "icmp" {
			if prt.type_ != -1 {
				if prt.code != -1 {
					up, ok := prt2obj[fmt.Sprint("icmp ", prt.type_)]
					if !ok {
						up = icmp_up
					}
					prt.up = up
				} else {
					prt.up = icmp_up
				}
			} else {
				prt.up = prt_ip
			}
		} else if _, err := strconv.Atoi(proto); err == nil {

			// Numeric protocol.
			prt.up = prt_ip
		}
	}

	order_ranges("tcp", prt2obj, prt_ip)
	order_ranges("udp", prt2obj, prt_ip)

	if tcp_establ, ok := prt2obj["tcp 1 65535 established"]; ok {
		up, ok := prt2obj["tcp 1 65535"]
		if !ok {
			up = prt_ip
		}
		tcp_establ.up = up
	}
}

/*
#sub print_rule {
#    my ($rule) = @_;
#    my ($deny, $src, $dst, $prt) = @{$rule}{qw(deny src dst prt)};
#    my $action = $deny ? 'deny' : 'permit';
#    return "$action $src->{name} $dst->{name} $prt->{name}";
#}
*/

func optimize_redundant_rules(cmp_hash, chg_hash Rule_tree) bool {
	changed := false
	for deny, chg_hash := range chg_hash {
		for {
			if cmp_hash, found := cmp_hash[deny]; found {
				for src_range, chg_hash := range chg_hash {
					for {
						if cmp_hash, found := cmp_hash[src_range]; found {
							for src, chg_hash := range chg_hash {
								for {
									if cmp_hash, found := cmp_hash[src]; found {
										for dst, chg_hash := range chg_hash {
											for {
												if cmp_hash, found := cmp_hash[dst]; found {
													for prt, chg_rule := range chg_hash {
														if chg_rule.deleted {
															continue
														}
														for {
															if cmp_rule, found := cmp_hash[prt]; found {
																if cmp_rule != chg_rule &&
																	cmp_rule.log == chg_rule.log {
																	chg_rule.deleted = true
																	changed = true
																	break
																}
															}
															prt = prt.up
															if prt == nil {
																break
															}
														}
													}
												}
												dst = dst.up
												if dst == nil {
													break
												}
											}
										}
									}
									src = src.up
									if src == nil {
										break
									}
								}
							}
						}
						src_range = src_range.up
						if src_range == nil {
							break
						}
					}
				}
			}
			if deny {
				break
			}
			deny = true
		}
	}
	return changed
}

type Rule struct {
	deny           bool
	src, dst       *IP_Net
	prt, src_range *Proto
	log            string
	deleted        bool
	opt_secondary  bool
}

type Rules []*Rule

func (rules *Rules) push(rule *Rule) {
	*rules = append(*rules, rule)
}

// Build rule tree from nested maps.
// Leaf nodes have rules as values.
type Rule_tree1 map[*Proto]*Rule
type Rule_tree2 map[*IP_Net]Rule_tree1
type Rule_tree3 map[*IP_Net]Rule_tree2
type Rule_tree4 map[*Proto]Rule_tree3
type Rule_tree map[bool]Rule_tree4

func (tree Rule_tree2) add(dst *IP_Net) Rule_tree1 {
	subtree, found := tree[dst]
	if !found {
		subtree = make(Rule_tree1)
		tree[dst] = subtree
	}
	return subtree
}
func (tree Rule_tree3) add(src *IP_Net) Rule_tree2 {
	subtree, found := tree[src]
	if !found {
		subtree = make(Rule_tree2)
		tree[src] = subtree
	}
	return subtree
}
func (tree Rule_tree4) add(src_range *Proto) Rule_tree3 {
	subtree, found := tree[src_range]
	if !found {
		subtree = make(Rule_tree3)
		tree[src_range] = subtree
	}
	return subtree
}
func (tree Rule_tree) add(deny bool) Rule_tree4 {
	subtree, found := tree[deny]
	if !found {
		subtree = make(Rule_tree4)
		tree[deny] = subtree
	}
	return subtree
}

/*
// Dynamically typed function adds next nesting levels.
// Map for subtrees is created if necessary.
func dyn_tree(tree interface{}, keys ...interface{}) interface{} {
	t := reflect.ValueOf(tree)
	for _, key := range keys {
		k := reflect.ValueOf(key)
		s := t.MapIndex(k)
		// Create new map if necessary.
		if !s.IsValid() {
			s = reflect.MakeMap(t.Type().Elem())
			t.SetMapIndex(k, s)
		}
		t = s
	}
	return t.Interface()
}
*/

func optimize_rules(rules Rules, acl_info *ACL_Info) Rules {
	prt_ip := acl_info.prt2obj["ip"]
	changed := false

	// Add rule to rule tree.
	add_rule := func(rule_tree Rule_tree, rule *Rule) {
		src_range := rule.src_range
		if src_range == nil {
			src_range = prt_ip
		}

		subtree1 :=
			rule_tree.add(rule.deny).add(src_range).add(rule.src).add(rule.dst)
		//// Build nested rule_tree by dynamically typed operations.
		//// Go back to static type 'Rule_tree1'.
		//	dyn_tree(rule_tree, rule.deny, src_range, rule.src, rule.dst).(Rule_tree1)
		if _, found := subtree1[rule.prt]; found {
			rule.deleted = true
			changed = true
		} else {
			subtree1[rule.prt] = rule
		}
	}

	// For comparing redundant rules.
	rule_tree := make(Rule_tree)

	// Fill rule tree.
	for _, rule := range rules {
		add_rule(rule_tree, rule)
	}

	changed = optimize_redundant_rules(rule_tree, rule_tree) || changed

	// Implement rules as secondary rule, if possible.
	secondary_tree := make(Rule_tree)
	for _, rule := range rules {
		if !rule.opt_secondary {
			continue
		}
		if rule.deleted {
			continue
		}
		if rule.src.no_opt_addrs {
			continue
		}
		if rule.dst.no_opt_addrs {
			continue
		}

		// Replace obj by supernet.
		if rule.src.opt_networks != nil {
			rule.src = rule.src.opt_networks
		}
		if rule.dst.opt_networks != nil && !rule.dst.need_protect {
			rule.dst = rule.dst.opt_networks
		}

		// Change protocol to IP.
		rule.prt = prt_ip

		add_rule(secondary_tree, rule)
	}

	if len(secondary_tree) != 0 {
		changed =
			optimize_redundant_rules(secondary_tree, secondary_tree) || changed
		changed =
			optimize_redundant_rules(secondary_tree, rule_tree) || changed
	}

	if changed {
		new_rules := make(Rules, 0)
		for _, rule := range rules {
			if rule.deleted {
				continue
			}
			new_rules.push(rule)
		}
		rules = new_rules
	}
	return rules
}

// Join adjacent port ranges.
func join_ranges(rules Rules, prt2obj Name2Proto) Rules {
	type key struct {
		deny       bool
		src, dst   *IP_Net
		src_range  *Proto
		log, proto string
	}
	changed := false
	key2rules := make(map[key]Rules)
	for _, rule := range rules {

		// Only ranges which have a neighbor may be successfully optimized.
		// Currently only dst_ranges are handled.
		if !rule.prt.has_neighbor {
			continue
		}

		// Collect rules with identical deny/src/dst/src_range log values
		// and identical TCP or UDP protocol.
		k := key{
			rule.deny, rule.src, rule.dst, rule.src_range, rule.log,
			rule.prt.proto,
		}
		key2rules[k] = append(key2rules[k], rule)
	}

	rule2range := make(map[*Rule][2]int)
	for _, sorted := range key2rules {
		if len(sorted) < 2 {
			continue
		}

		// When sorting these rules by low port number, rules with
		// adjacent protocols will placed side by side. There can't be
		// overlaps, because they have been split in function
		// 'order_ranges'. There can't be sub-ranges, because they have
		// been deleted as redundant already.
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i].prt.ports[0] < sorted[j].prt.ports[0]
		})
		rule_a := sorted[0]
		a1, a2 := rule_a.prt.ports[0], rule_a.prt.ports[1]
		for _, rule_b := range sorted[1:] {
			b1, b2 := rule_b.prt.ports[0], rule_b.prt.ports[1]

			// Found adjacent port ranges.
			if a2+1 == b1 {

				// Extend range of previous two or more elements.
				if ports, ok := rule2range[rule_a]; ok {

					ports[1] = b2
					rule2range[rule_b] = ports
					delete(rule2range, rule_a)
				} else {

					// Combine ranges of $rule_a and $rule_b.
					rule2range[rule_b] = [...]int{a1, b2}
				}

				// Mark previous rule as deleted.
				rule_a.deleted = true
				changed = true
			}
			rule_a = rule_b
			a1, a2 = b1, b2
		}
	}

	if changed {
		var new_rules Rules
		for _, rule := range rules {

			// Ignore deleted rules
			if rule.deleted {
				continue
			}

			// Process rule with joined port ranges.
			if ports, ok := rule2range[rule]; ok {
				proto := rule.prt.proto
				key := fmt.Sprintf("%s %d %d", proto, ports[0], ports[1])

				// Try to find existing prt with matching range.
				// This is needed for find_objectgroups to work.
				new_prt, ok := prt2obj[key]
				if !ok {
					new_prt = &Proto{proto: proto, ports: ports}
					prt2obj[key] = new_prt
				}
				rule.prt = new_prt
			}
			new_rules.push(rule)
		}
		rules = new_rules
	}
	return rules
}

type ACL_Info struct {
	name                                                  string
	is_std_acl                                            bool
	intf_rules, rules                                     Rules
	lrules                                                Linux_Rules
	prt2obj                                               Name2Proto
	ip_net2obj                                            Name2IP_Net
	filter_only, opt_networks, no_opt_addrs, need_protect []*IP_Net
	filter_any_src                                        bool
	network_00                                            *IP_Net
	prt_ip                                                *Proto
	object_groups                                         []*Obj_Group
}

// Place those rules first in Cisco ACL that have
// - attribute 'log'
//   because larger rule must not be placed before them,
// - protocols ESP or AH
//   for performance reasons.
// Crypto rules need to have a fixed order,
// Protocols ESP and AH are be placed first in Cisco ACL
// for performance reasons.
// These rules need to have a fixed order.
// Otherwise the connection may be lost,
// - if the device is accessed over an IPSec tunnel
// - and we change the ACL incrementally.
func move_rules_esp_ah(rules Rules, prt2obj Name2Proto, has_log bool) Rules {
	prt_esp := prt2obj["50"]
	prt_ah := prt2obj["51"]
	if prt_esp == nil && prt_ah == nil && !has_log {
		return rules
	}
	if rules == nil {
		return nil
	}
	var deny_rules, crypto_rules, permit_rules Rules
	for _, rule := range rules {
		if rule.deny {
			deny_rules.push(rule)
		} else if rule.prt == prt_esp || rule.prt == prt_ah || rule.log != "" {
			crypto_rules.push(rule)
		} else {
			permit_rules.push(rule)
		}
	}

	// Sort crypto rules.
	cmp_addr := func(a, b *IP_Net) int {
		if val := bytes.Compare(a.IP, b.IP); val != 0 {
			return val
		}
		return bytes.Compare(a.Mask, b.Mask)
	}
	sort.Slice(crypto_rules, func(i, j int) bool {
		switch strings.Compare(
			crypto_rules[i].prt.proto,
			crypto_rules[j].prt.proto) {
		case -1:
			return true
		case 1:
			return false
		}
		switch cmp_addr(crypto_rules[i].src, crypto_rules[j].src) {
		case -1:
			return true
		case 1:
			return false
		}
		return cmp_addr(crypto_rules[i].dst, crypto_rules[j].dst) == -1
	})
	return append(deny_rules, append(crypto_rules, permit_rules...)...)
}

func create_group(elements []*IP_Net, acl_info *ACL_Info, router_data *Router_Data) *Obj_Group {
	name := fmt.Sprintf("g%d", router_data.obj_group_counter)
	group_ref := &IP_Net{IPNet: nil, name: name}
	group := &Obj_Group{
		name:     name,
		elements: elements,
		ref:      group_ref,
	}
	router_data.obj_group_counter++

	// Store group for later printing of its definition.
	acl_info.object_groups = append(acl_info.object_groups, group)
	return group
}

// Add deny and permit rules at device which filters only locally.
func add_local_deny_rules(acl_info *ACL_Info, router_data *Router_Data) {
	network_00, prt_ip := acl_info.network_00, acl_info.prt_ip
	filter_only := acl_info.filter_only
	var src_networks []*IP_Net
	if acl_info.filter_any_src {
		src_networks = []*IP_Net{network_00}
	} else {
		src_networks = filter_only
	}

	if router_data.do_objectgroup {
		group_or_single := func(obj_list []*IP_Net) *IP_Net {
			if len(obj_list) == 1 {
				return obj_list[0]
			} else if router_data.filter_only_group != nil {

				// Reuse object-group at all interfaces.
				return router_data.filter_only_group
			} else {
				group := create_group(obj_list, acl_info, router_data)
				router_data.filter_only_group = group.ref
				return group.ref
			}
		}
		acl_info.rules.push(
			&Rule{
				deny: true,
				src:  group_or_single(src_networks),
				dst:  group_or_single(filter_only),
				prt:  prt_ip,
			})
	} else {
		for _, src := range src_networks {
			for _, dst := range filter_only {
				acl_info.rules.push(
					&Rule{deny: true, src: src, dst: dst, prt: prt_ip})
			}
		}
	}
	acl_info.rules.push(
		&Rule{src: network_00, dst: network_00, prt: prt_ip})
}

/*
 Purpose    : Create a list of IP/mask objects from a hash of IP/mask names.
              Adjacent IP/mask objects are combined to larger objects.
              It is assumed, that no duplicate or redundant IP/mask objects
              are given.
 Parameters : $hash - hash with IP/mask objects as keys and
                      rules as values.
              $ip_net2obj - hash of all known IP/mask objects
 Result     : Returns reference to array of sorted and combined
              IP/mask objects.
              Parameter $hash is changed to reflect combined IP/mask objects.
*/
func combine_adjacent_ip_mask(hash map[*IP_Net]*Rule, ip_net2obj Name2IP_Net) []*IP_Net {

	// Take objects from keys of map.
	// Sort by mask. Adjacent networks will be adjacent elements then.
	elements := make([]*IP_Net, 0, len(hash))
	for element := range hash {
		elements = append(elements, element)
	}
	sort.Slice(elements, func(i, j int) bool {
		switch bytes.Compare(elements[i].IP, elements[j].IP) {
		case -1:
			return true
		case 1:
			return false
		}
		return bytes.Compare(elements[i].Mask, elements[j].Mask) == -1
	})

	// Find left and rigth part with identical mask and combine them
	// into next larger network.
	// Compare up to last but one element.
	for i := 0; i < len(elements)-1; i++ {
		element1 := elements[i]
		element2 := elements[i+1]
		mask := element1.Mask
		if bytes.Compare(mask, element2.Mask) != 0 {
			continue
		}
		prefix, bits := mask.Size()
		prefix--
		up_mask := net.CIDRMask(prefix, bits)
		ip1 := element1.IP
		ip2 := element2.IP
		if bytes.Compare(ip1.Mask(up_mask), ip2.Mask(up_mask)) != 0 {
			continue
		}
		up_element := get_ip_obj(ip1, up_mask, ip_net2obj)

		// Substitute left part by combined network.
		elements[i] = up_element

		// Remove right part.
		elements = append(elements[:i+1], elements[i+2:]...)

		// Add new element and remove left and rigth parts.
		hash[up_element] = hash[element1]
		delete(hash, element1)
		delete(hash, element2)

		if i > 0 {
			up2_mask := net.CIDRMask(prefix-1, bits)

			// Check previous network again, if newly created network
			// is right part, i.e. lowest bit of network part is set.
			if !ip1.Equal(ip1.Mask(up2_mask)) {
				i--
			}
		}

		// Only one element left.
		// Condition of for-loop isn't effective, because of 'i--' below.
		if i >= len(elements)-1 {
			break
		}

		// Compare current network again.
		i--
	}
	return elements
}

const min_object_group_size = 2

type Obj_Group struct {
	name     string
	elements []*IP_Net
	ref      *IP_Net
	hash     map[string]bool
}

// For searching efficiently for matching group.
type group_key struct {
	size  int
	first string
}

func find_objectgroups(acl_info *ACL_Info, router_data *Router_Data) {
	ip_net2obj := acl_info.ip_net2obj

	// Reuse identical groups from different ACLs.
	if router_data.obj_groups_hash == nil {
		router_data.obj_groups_hash = make(map[group_key][]*Obj_Group)
	}
	key2group := router_data.obj_groups_hash

	// Leave 'intf_rules' untouched, because
	// - these rules are ignored at ASA,
	// - NX-OS needs them individually when optimizing need_protect.
	rules := acl_info.rules

	// Find object-groups in src / dst of rules.
	for _, this_is_dst := range []bool{false, true} {
		type key struct {
			deny           bool
			that           *IP_Net
			src_range, prt *Proto
			log            string
		}
		group_rule_tree := make(map[key]map[*IP_Net]*Rule)

		// Find groups of rules with identical
		// deny, src_range, prt, log, src/dst and different dst/src.
		for _, rule := range rules {
			deny := rule.deny
			src_range := rule.src_range
			prt := rule.prt
			log := rule.log
			this := rule.src
			that := rule.dst
			if this_is_dst {
				this, that = that, this
			}
			k := key{deny, that, src_range, prt, log}
			href, ok := group_rule_tree[k]
			if !ok {
				href = make(map[*IP_Net]*Rule)
				group_rule_tree[k] = href
			}
			href[this] = rule
		}

		// Find groups >= min_object_group_size,
		// mark rules belonging to one group.
		type glue_type struct {

			// Indicator, that group has already been added to some rule.
			active bool

			// object-key => rule, ...
			hash map[*IP_Net]*Rule
		}
		group_glue := make(map[*Rule]*glue_type)
		for _, href := range group_rule_tree {

			// href is {dst/src => rule, ...}
			if len(href) < min_object_group_size {
				continue
			}

			glue := glue_type{hash: href}

			// All this rules have identical deny, src_range, prt
			// and dst/src and shall be replaced by a single new
			// rule referencing an object group.
			for _, rule := range href {
				group_glue[rule] = &glue
			}
		}

		// Find group with identical elements
		// or define a new one
		// or return combined network.
		// Returns IP_Net object with empty IP, representing a group.
		get_group := func(hash map[*IP_Net]*Rule) *IP_Net {

			// Get sorted and combined list of objects from hash of objects.
			// Hash is adjusted, if objects are combined.
			elements := combine_adjacent_ip_mask(hash, ip_net2obj)
			size := len(elements)

			// If all elements have been combined into one single network,
			// don't create a group, but take single element as result.
			if size == 1 {
				return elements[0]
			}

			// Use size and first element as keys for efficient lookup.
			// Name of element is used, because elements are regenerated
			// between processing of different ACLs.
			first := elements[0]
			key := group_key{size, first.name}

			// Search group with identical elements.
			if groups, ok := key2group[key]; ok {
			HASH:
				for _, group := range groups {
					href := group.hash

					// Check elements for equality.
					for key := range hash {
						if _, ok := href[key.name]; !ok {
							continue HASH
						}
					}

					// Found group with matching elements.
					return group.ref
				}
			}

			// No group found, build new group.
			group := create_group(elements, acl_info, router_data)
			names_in_group := make(map[string]bool, len(hash))
			for element := range hash {
				names_in_group[element.name] = true
			}
			group.hash = names_in_group
			key2group[key] = append(key2group[key], group)
			return group.ref
		}

		// Build new list of rules using object groups.
		new_rules := make(Rules, 0)
		for _, rule := range rules {
			if glue, ok := group_glue[rule]; ok {
				if glue.active {
					continue
				}
				glue.active = true
				group_or_obj := get_group(glue.hash)
				if this_is_dst {
					rule.dst = group_or_obj
				} else {
					rule.src = group_or_obj
				}
			}
			new_rules = append(new_rules, rule)
		}
		rules = new_rules
	}
	acl_info.rules = rules
}

func add_protect_rules(acl_info *ACL_Info, has_final_permit bool) {
	need_protect := acl_info.need_protect
	if len(need_protect) == 0 {
		return
	}
	network_00, prt_ip := acl_info.network_00, acl_info.prt_ip

	// Add deny rules to protect own interfaces.
	// If a rule permits traffic to a directly connected network behind
	// the device, this would accidently permit traffic to an interface
	// of this device as well.

	// To be added deny rule is needless if there is a rule which
	// permits any traffic to the interface.
	// This permit rule can be deleted if there is a permit any any rule.
	no_protect := make(map[*IP_Net]bool)
	var deleted int
	rules := acl_info.intf_rules
	for i, rule := range rules {
		if rule.deny {
			continue
		}
		if rule.src != network_00 {
			continue
		}
		if rule.prt != prt_ip {
			continue
		}
		dst := rule.dst
		if dst.need_protect {
			no_protect[dst] = true
		}

		if has_final_permit {
			rules[i] = nil
			deleted++
		}
	}
	if deleted != 0 {
		new_rules := make(Rules, 0, len(rules)-deleted)
		for _, rule := range rules {
			if rule != nil {
				new_rules.push(rule)
			}
		}
		acl_info.intf_rules = new_rules
	}

	// Deny rule is needless if there is no such permit rule.
	// Try to optimize this case.
	protect_map := make(map[*IP_Net]bool)
	for _, rule := range acl_info.rules {
		if rule.deny {
			continue
		}
		if rule.prt.established {
			continue
		}
		hash := rule.dst.is_supernet_of_need_protect
		if hash == nil {
			continue
		}
		for _, intf := range need_protect {
			if hash[intf] {
				protect_map[intf] = true
			}
		}
	}

	// Protect own interfaces.
	for _, intf := range need_protect {
		if no_protect[intf] || !protect_map[intf] && !has_final_permit {
			continue
		}
		acl_info.intf_rules.push(
			&Rule{
				deny: true,
				src:  network_00,
				dst:  intf,
				prt:  prt_ip,
			})
	}
}

// Check if last rule is 'permit ip any any'.
func check_final_permit(acl_info *ACL_Info) bool {
	rules := acl_info.rules
	l := len(rules)
	if l == 0 {
		return false
	}
	last := rules[l-1]
	return !last.deny &&
		last.src == acl_info.network_00 &&
		last.dst == acl_info.network_00 &&
		last.prt == acl_info.prt_ip
}

// Add 'deny|permit ip any any' at end of ACL.
func add_final_permit_deny_rule(acl_info *ACL_Info, add_deny, add_permit bool) {
	if add_deny || add_permit {
		acl_info.rules.push(
			&Rule{
				deny: add_deny,
				src:  acl_info.network_00,
				dst:  acl_info.network_00,
				prt:  acl_info.prt_ip,
			})
	}
}

// Returns iptables code for filtering a protocol.
func iptables_prt_code(src_range_node, prt_node *Prt_bintree) string {
	prt := &prt_node.Proto
	proto := prt.proto
	result := "-p " + proto
	switch proto {
	case "tcp", "udp":
		port_code := func(range_obj *Proto) string {
			ports := range_obj.ports
			v1, v2 := ports[0], ports[1]
			if v1 == v2 {
				return fmt.Sprint(v1)
			} else if v1 == 1 && v2 == 65535 {
				return ""
			} else if v2 == 65535 {
				return fmt.Sprint(v1, ":")
			} else if v1 == 1 {
				return fmt.Sprint(":", v2)
			} else {
				return fmt.Sprint(v1, ":", v2)
			}
		}
		if src_range_node != nil {
			if sport := port_code(&src_range_node.Proto); sport != "" {
				result += " --sport " + sport
			}
		}
		if dport := port_code(prt); dport != "" {
			result += " --dport " + dport
		}
		return result
	case "icmp":
		type_ := prt.type_
		if type_ != -1 {
			code := prt.code
			if code != -1 {
				return fmt.Sprintf("%s --icmp-type %d/%d", result, type_, code)
			} else {
				return fmt.Sprintf("%s --icmp-type %d", result, type_)
			}
		} else {
			return result
		}
	default:
		return result
	}
}

// Handle iptables.
/*
func debug_bintree (tree *Net_bintree, depth string) {
	ip      := tree.IP.String()
	len, _  := tree.Mask.Size()
   var subtree string
	if tree.subtree != nil {
		subtree = "subtree";
	}
	info("%s %s/%d %s", depth, ip, len, subtree)
	if lo := tree.lo; lo != nil {
		debug_bintree(lo, depth + "l")
	}
	if hi := tree.hi; hi != nil {
		debug_bintree(hi, depth + "r")
	}
}
*/

// Value is Lrule_tree.
type Lrule_tree map[Net_or_Prot]*Lrule_tree

type Net_bintree struct {
	IP_Net
	subtree NP_bintree
	hi      *Net_bintree
	lo      *Net_bintree
	noop    bool
}

// Nodes are reverse sorted before being added to bintree.
// Redundant nodes are discarded while inserting.
// A node with value of sub-tree S is discarded,
// if some parent node already has sub-tree S.
func add_bintree(tree *Net_bintree, node *Net_bintree) *Net_bintree {
	tree_ip, tree_mask := tree.IP, tree.Mask
	node_ip, node_mask := node.IP, node.Mask
	prefix, bits := tree_mask.Size()
	node_pref, _ := node_mask.Size()
	var result *Net_bintree

	// The case where new node is larger than root node will never
	// occur, because nodes are sorted before being added.

	if prefix < node_pref && tree.Contains(node_ip) {

		// Optimization for this special case:
		// Root of tree has attribute {subtree} which is identical to
		// attribute {subtree} of current node.
		// Node is known to be less than root node.
		// Hence node together with its subtree can be discarded
		// because it is redundant compared to root node.
		// ToDo:
		// If this optimization had been done before merge_subtrees,
		// it could have merged more subtrees.
		if tree.subtree == nil || node.subtree == nil ||
			tree.subtree != node.subtree {
			mask := net.CIDRMask(prefix+1, bits)
			var hilo **Net_bintree
			if node_ip.Mask(mask).Equal(tree_ip) {
				hilo = &tree.lo
			} else {
				hilo = &tree.hi
			}
			if *hilo != nil {
				*hilo = add_bintree(*hilo, node)
			} else {
				*hilo = node
			}
		}
		result = tree
	} else {

		// Create common root for tree and node.
		for {
			prefix--
			tree_mask = net.CIDRMask(prefix, bits)
			if node_ip.Mask(tree_mask).Equal(tree_ip.Mask(tree_mask)) {
				break
			}
		}
		result = &Net_bintree{
			IP_Net: IP_Net{
				IPNet: &net.IPNet{IP: node_ip.Mask(tree_mask), Mask: tree_mask}},
		}
		if bytes.Compare(node_ip, tree_ip) < 0 {
			result.lo, result.hi = node, tree
		} else {
			result.hi, result.lo = node, tree
		}
	}

	// Merge adjacent sub-networks.
	if result.subtree == nil {
		lo, hi := result.lo, result.hi
		if lo == nil || hi == nil {
			goto NO_MERGE
		}
		prefix, _ := result.Mask.Size()
		prefix++
		if lo_prefix, _ := lo.Mask.Size(); prefix != lo_prefix {
			goto NO_MERGE
		}
		if hi_prefix, _ := hi.Mask.Size(); prefix != hi_prefix {
			goto NO_MERGE
		}
		if lo.subtree == nil || hi.subtree == nil {
			goto NO_MERGE
		}
		if lo.subtree != hi.subtree {
			goto NO_MERGE
		}
		if lo.lo != nil || lo.hi != nil || hi.lo != nil || hi.hi != nil {
			goto NO_MERGE
		}
		result.subtree = lo.subtree
		result.lo = nil
		result.hi = nil
	}
NO_MERGE:
	return result
}

type Net_or_Prot interface {
}

// Build a binary tree for src/dst objects.
func gen_addr_bintree(
	elements []*IP_Net,
	tree Lrule_tree,
	tree2bintree map[*Lrule_tree]NP_bintree) *Net_bintree {

	// The tree's node is a simplified network object with
	// missing attribute 'name' and extra 'subtree'.
	nodes := make([]*Net_bintree, len(elements))
	for i, elem := range elements {
		nodes[i] = &Net_bintree{
			IP_Net:  *elem,
			subtree: tree2bintree[tree[elem]],
		}
	}

	// Sort by mask size and then by IP.
	// I.e. large networks coming first.
	sort.Slice(nodes, func(i, j int) bool {
		switch bytes.Compare(nodes[i].Mask, nodes[j].Mask) {
		case -1:
			return true
		case 1:
			return false
		}
		return bytes.Compare(nodes[i].IP, nodes[j].IP) == 1
	})

	var bintree *Net_bintree
	bintree, nodes = nodes[0], nodes[1:]
	for len(nodes) > 0 {
		var node *Net_bintree
		node, nodes = nodes[0], nodes[1:]
		bintree = add_bintree(bintree, node)
	}

	// Add attribute {noop} to node which doesn't add any test to
	// generated rule.
	if prefix, _ := bintree.Mask.Size(); prefix == 0 {
		bintree.noop = true
	}

	//	debug_bintree(bintree, "")
	return bintree
}

func (tree *Net_bintree) Hi() NP_bintree {
	if hi := tree.hi; hi != nil {
		return hi
	} else {
		return nil
	}
}
func (tree *Net_bintree) Lo() NP_bintree {
	if lo := tree.lo; lo != nil {
		return lo
	} else {
		return nil
	}
}
func (tree *Net_bintree) Seq() []*Prt_bintree { return nil }
func (tree *Net_bintree) Subtree() NP_bintree {
	if subtree := tree.subtree; subtree != nil {
		return subtree
	} else {
		return nil
	}
}
func (tree *Net_bintree) Noop() bool { return tree.noop }

// Build a tree for src-range/prt objects. Sub-trees for tcp and udp
// will be binary trees. Nodes have attributes {proto}, {range},
// {type}, {code} like protocols (but without {name}).
// Additional attributes for building the tree:
// For tcp and udp:
// {lo}, {hi} for sub-ranges of current node.
// For other protocols:
// {seq} an array of ordered nodes for sub protocols of current node.
// Elements of {lo} and {hi} or elements of {seq} are guaranteed to be
// disjoint.
// Additional attribute {subtree} is set with corresponding subtree of
// protocol object if current node comes from a rule and wasn't inserted
// for optimization.

type Prt_bintree struct {
	Proto
	subtree NP_bintree
	hi      *Prt_bintree
	lo      *Prt_bintree
	seq     []*Prt_bintree
	noop    bool
}

func gen_prt_bintree(
	elements []*Proto,
	tree Lrule_tree,
	tree2bintree map[*Lrule_tree]NP_bintree) *Prt_bintree {
	var ip_prt *Proto
	top_prt := make(map[string][]*Proto)
	sub_prt := make(map[*Proto][]*Proto)

	// Add all protocols directly below protocol 'ip' into map top_prt
	// grouped by protocol. Add protocols below top protocols or below
	// other protocols of current set of protocols to map sub_prt.
PRT:
	for _, prt := range elements {
		proto := prt.proto
		if proto == "ip" {
			ip_prt = prt
			continue PRT
		}

		// Check if prt is sub protocol of any other protocol of
		// current set. But handle direct sub protocols of 'ip' as top
		// protocols.
		for up := prt.up; up.up != nil; up = up.up {
			if subtree, ok := tree[up]; ok {

				// Found sub protocol of current set.
				// Optimization:
				// Ignore the sub protocol if both protocols have
				// identical subtrees.
				// In this case we found a redundant sub protocol.
				if tree[prt] != subtree {
					sub_prt[up] = append(sub_prt[up], prt)
				}
				continue PRT
			}
		}

		// Not a sub protocol (except possibly of IP).
		var key string
		if _, err := strconv.ParseUint(proto, 10, 16); err == nil {
			key = "proto"
		} else {
			key = proto
		}
		top_prt[key] = append(top_prt[key], prt)
	}

	// Collect subtrees for tcp, udp, proto and icmp.
	var seq []*Prt_bintree

	//Build subtree of tcp and udp protocols.
	//
	// We need not to handle 'tcp established' because it is only used
	// for stateless routers, but iptables is stateful.
	var gen_lohitrees func(prt_aref []*Proto) (*Prt_bintree, *Prt_bintree)
	var gen_rangetree func(prt_aref []*Proto) *Prt_bintree
	gen_lohitrees = func(prt_aref []*Proto) (*Prt_bintree, *Prt_bintree) {
		switch len(prt_aref) {
		case 0:
			return nil, nil
		case 1:
			prt := prt_aref[0]
			lo, hi := gen_lohitrees(sub_prt[prt])
			node := &Prt_bintree{
				Proto:   *prt,
				subtree: tree2bintree[tree[prt]],
				lo:      lo,
				hi:      hi,
			}
			return node, nil
		default:
			ports := make([]*Proto, len(prt_aref))
			copy(ports, prt_aref)
			sort.Slice(ports, func(i, j int) bool {
				return ports[i].ports[0] < ports[j].ports[0]
			})

			// Split array in two halves (prefer larger left part).
			mid := (len(ports)-1)/2 + 1
			left := ports[:mid]
			right := ports[mid:]
			return gen_rangetree(left), gen_rangetree(right)
		}
	}
	gen_rangetree = func(prt_aref []*Proto) *Prt_bintree {
		lo, hi := gen_lohitrees(prt_aref)
		if hi == nil {
			return lo
		}

		// Take low port from lower tree and high port from high tree.
		prt := *prt_aref[0]
		prt.ports = [2]int{lo.ports[0], hi.ports[1]}

		// Merge adjacent port ranges.
		if lo.ports[1]+1 == hi.ports[0] &&
			lo.subtree != nil && hi.subtree != nil && lo.subtree == hi.subtree {

			hilo := make([]*Prt_bintree, 0, 4)
			for _, what := range []*Prt_bintree{lo.lo, lo.hi, hi.lo, hi.hi} {
				if what != nil {
					hilo = append(hilo, what)
				}
			}
			if len(hilo) <= 2 {

				//		debug("Merged: $lo->{range}->[0]-$lo->{range}->[1]",
				//		      " $hi->{range}->[0]-$hi->{range}->[1]");
				node := &Prt_bintree{
					Proto:   prt,
					subtree: lo.subtree,
				}
				if len(hilo) > 0 {
					node.lo = hilo[0]
				}
				if len(hilo) > 1 {
					node.hi = hilo[1]
				}
				return node
			}
		}
		return &Prt_bintree{
			Proto: prt,
			lo:    lo,
			hi:    hi,
		}
	}
	for _, what := range []string{"tcp", "udp"} {
		if aref, ok := top_prt[what]; ok {
			seq = append(seq, gen_rangetree(aref))
		}
	}

	// Add single nodes for numeric protocols.
	if aref, ok := top_prt["proto"]; ok {
		sort.Slice(aref, func(i, j int) bool {
			return aref[i].proto < aref[j].proto
		})
		for _, prt := range aref {
			node := &Prt_bintree{Proto: *prt, subtree: tree2bintree[tree[prt]]}
			seq = append(seq, node)
		}
	}

	// Build subtree of icmp protocols.
	if icmp_aref, ok := top_prt["icmp"]; ok {
		type2prt := make(map[int][]*Proto)
		var icmp_any *Proto

		// If one protocol is 'icmp any' it is the only top protocol,
		// all other icmp protocols are sub protocols.
		if icmp_aref[0].type_ == -1 {
			icmp_any = icmp_aref[0]
			icmp_aref = sub_prt[icmp_any]
		}

		// Process icmp protocols having defined type and possibly defined code.
		// Group protocols by type.
		for _, prt := range icmp_aref {
			type_ := prt.type_
			type2prt[type_] = append(type2prt[type_], prt)
		}

		// Parameter is array of icmp protocols all having
		// the same type and different but defined code.
		// Return reference to array of nodes sorted by code.
		gen_icmp_type_code_sorted := func(aref []*Proto) []*Prt_bintree {
			sort.Slice(aref, func(i, j int) bool {
				return aref[i].code < aref[j].code
			})
			result := make([]*Prt_bintree, len(aref))
			for i, proto := range aref {
				result[i] = &Prt_bintree{
					Proto:   *proto,
					subtree: tree2bintree[tree[proto]],
				}
			}
			return result
		}

		// For collecting subtrees of icmp subtree.
		var seq2 []*Prt_bintree

		// Process grouped icmp protocols having the same type.
		types := make([]int, 0, len(type2prt))
		for type_ := range type2prt {
			types = append(types, type_)
		}
		sort.Ints(types)
		for _, type_ := range types {
			aref2 := type2prt[type_]
			var node2 *Prt_bintree

			// If there is more than one protocol,
			// all have same type and defined code.
			if len(aref2) > 1 {
				seq3 := gen_icmp_type_code_sorted(aref2)

				// Add a node 'icmp type any' as root.
				node2 = &Prt_bintree{
					Proto: Proto{proto: "icmp", type_: type_, code: -1},
					seq:   seq3,
				}
			} else {

				// One protocol 'icmp type any'.
				prt := aref2[0]
				node2 = &Prt_bintree{
					Proto:   *prt,
					subtree: tree2bintree[tree[prt]],
				}
				if aref3, ok := sub_prt[prt]; ok {
					node2.seq = gen_icmp_type_code_sorted(aref3)
				}
			}
			seq2 = append(seq2, node2)
		}

		// Add root node for icmp subtree.
		var node *Prt_bintree
		if icmp_any != nil {
			node = &Prt_bintree{
				Proto:   *icmp_any,
				seq:     seq2,
				subtree: tree2bintree[tree[icmp_any]],
			}
		} else if len(seq2) > 1 {
			node = &Prt_bintree{
				Proto: Proto{proto: "icmp", type_: -1, code: -1},
				seq:   seq2,
			}
		} else {
			node = seq2[0]
		}
		seq = append(seq, node)
	}

	// Add root node for whole tree.
	var bintree *Prt_bintree
	if ip_prt != nil {
		bintree = &Prt_bintree{
			Proto:   *ip_prt,
			seq:     seq,
			subtree: tree2bintree[tree[ip_prt]],
		}
	} else if len(seq) > 1 {
		bintree = &Prt_bintree{Proto: Proto{proto: "ip"}, seq: seq}
	} else {
		bintree = seq[0]
	}

	// Add attribute {noop} to node which doesn't need any test in
	// generated chain.
	if bintree.proto == "ip" {
		bintree.noop = true
	}
	return bintree
}

func (tree *Prt_bintree) Hi() NP_bintree {
	if hi := tree.hi; hi != nil {
		return hi
	} else {
		return nil
	}
}
func (tree *Prt_bintree) Lo() NP_bintree {
	if lo := tree.lo; lo != nil {
		return lo
	} else {
		return nil
	}
}
func (tree *Prt_bintree) Seq() []*Prt_bintree { return tree.seq }
func (tree *Prt_bintree) Subtree() NP_bintree {
	if subtree := tree.subtree; subtree != nil {
		return subtree
	} else {
		return nil
	}
}
func (tree *Prt_bintree) Noop() bool { return tree.noop }

type Order [4]struct {
	count int
	get   func(*Rule) interface{}
	set   func(*Linux_Rule, interface{})
	name  string
}
type Chain struct {
	name  string
	rules Linux_Rules
}
type NP_bintree interface {
	Hi() NP_bintree
	Lo() NP_bintree
	Seq() []*Prt_bintree
	Subtree() NP_bintree
	Noop() bool
}

type Linux_Rule struct {
	deny           bool
	src, dst       *Net_bintree
	prt, src_range *Prt_bintree
	chain          *Chain
	goto_          bool
}

type Linux_Rules []*Linux_Rule

func (rules *Linux_Rules) push(rule *Linux_Rule) {
	*rules = append(*rules, rule)
}

func find_chains(acl_info *ACL_Info, router_data *Router_Data) {
	rules := acl_info.rules
	prt2obj := acl_info.prt2obj
	prt_ip := prt2obj["ip"]
	prt_icmp := prt2obj["icmp"]
	prt_tcp := prt2obj["tcp 1 65535"]
	prt_udp := prt2obj["udp 1 65535"]
	network_00 := acl_info.network_00

	// Specify protocols tcp, udp, icmp in
	// {src_range}, to get more efficient chains.
	for _, rule := range rules {
		src_range := rule.src_range
		if src_range == nil {
			switch rule.prt.proto {
			case "tcp":
				src_range = prt_tcp
			case "udp":
				src_range = prt_udp
			case "icmp":
				src_range = prt_icmp
			default:
				src_range = prt_ip
			}
		}
		rule.src_range = src_range
	}

	//    my $print_tree;
	//    $print_tree = sub {
	//        my ($tree, $order, $depth) = @_;
	//        for my $name (keys %$tree) {
	//
	//            debug(' ' x $depth, $name);
	//            if ($depth < $#$order) {
	//                $print_tree->($tree->{$name}, $order, $depth + 1);
	//            }
	//        }
	//    };

	coded_Lpermit := &Lrule_tree{false: nil}
	coded_Ldeny := &Lrule_tree{true: nil}
	coded_Bpermit := &Net_bintree{noop: false}
	coded_Bdeny := &Net_bintree{noop: true}
	subtree2bintree := make(map[*Lrule_tree]NP_bintree)
	subtree2bintree[coded_Ldeny] = coded_Bdeny
	subtree2bintree[coded_Lpermit] = coded_Bpermit

	insert_bintree := func(tree *Lrule_tree) NP_bintree {
		var elem1 interface{}
		for key := range *tree {
			elem1 = key
			break
		}
		switch elem1.(type) {
		case *IP_Net:
			elements := make([]*IP_Net, 0, len(*tree))
			for key := range *tree {
				elements = append(elements, key.(*IP_Net))
			}

			// Put prt/src/dst objects at the root of some subtree into a
			// (binary) tree. This is used later to convert subsequent tests
			// for ip/mask or port ranges into more efficient nested chains.
			return gen_addr_bintree(elements, *tree, subtree2bintree)
		case *Proto:
			elements := make([]*Proto, 0, len(*tree))
			for key := range *tree {
				elements = append(elements, key.(*Proto))
			}
			return gen_prt_bintree(elements, *tree, subtree2bintree)
		}
		return nil
	}

	// Used by $merge_subtrees1 to find identical subtrees.
	// Use hash for efficient lookup.
	type lookup struct {
		depth int
		size  int
	}
	depth2size2subtrees := make(map[lookup][]*Lrule_tree)

	// Find and merge identical subtrees.
	// Create bintree from subtree and store in subtree2bintree.
	merge_subtrees1 := func(tree *Lrule_tree, depth int) {

	SUBTREE:
		for k, subtree := range *tree {
			size := len(*subtree)
			l := lookup{depth, size}

			// Find subtree with identical keys and values;
		FIND:
			for _, subtree2 := range depth2size2subtrees[l] {
				for key, val := range *subtree {
					if val2, ok := (*subtree2)[key]; !ok || val2 != val {
						continue FIND
					}
				}

				// Substitute current subtree with identical subtree2
				(*tree)[k] = subtree2
				continue SUBTREE
			}

			// Found a new subtree.
			depth2size2subtrees[l] = append(depth2size2subtrees[l], subtree)
			bintree := insert_bintree(subtree)
			subtree2bintree[subtree] = bintree
		}
	}

	merge_subtrees := func(tree *Lrule_tree) NP_bintree {

		// Process leaf nodes first.
		for _, tree1 := range *tree {
			for _, tree2 := range *tree1 {
				merge_subtrees1(tree2, 2)
			}
		}

		// Process nodes next to leaf nodes.
		for _, tree1 := range *tree {
			merge_subtrees1(tree1, 1)
		}

		// Process nodes next to root.
		merge_subtrees1(tree, 0)
		return insert_bintree(tree)
	}

	// Add new chain to current router.
	new_chain := func(rules Linux_Rules) *Chain {
		router_data.chain_counter++
		chain := &Chain{
			name:  fmt.Sprintf("c%d", router_data.chain_counter),
			rules: rules,
		}
		router_data.chains = append(router_data.chains, chain)
		return chain
	}

	get_seq := func(bintree NP_bintree) []NP_bintree {
		seq := bintree.Seq()
		var result []NP_bintree
		if seq == nil {
			if hi := bintree.Hi(); hi != nil {
				result = append(result, hi)
			}
			if lo := bintree.Lo(); lo != nil {
				result = append(result, lo)
			}
		} else {
			result = make([]NP_bintree, len(seq))
			for i, v := range seq {
				result[i] = v
			}
		}
		return result
	}

	cache := make(map[NP_bintree]Linux_Rules)

	var gen_chain func(tree NP_bintree, order *Order, depth int) Linux_Rules
	gen_chain = func(tree NP_bintree, order *Order, depth int) Linux_Rules {
		setter := order[depth].set
		var new_rules Linux_Rules

		// We need the original value later.
		bintree := tree
		for {
			seq := get_seq(bintree)
			subtree := bintree.Subtree()
			if subtree != nil {
				/*
				   if($order->[$depth+1]&&
				      $order->[$depth+1] =~ /^(src|dst)$/) {
				       debug($order->[$depth+1]);
				       debug_bintree($subtree);
				   }
				*/
				rules := cache[subtree]
				if rules == nil {
					if depth+1 >= len(order) {
						rules = Linux_Rules{{deny: subtree.(*Net_bintree).noop}}
					} else {
						rules = gen_chain(subtree, order, depth+1)
					}
					if len(rules) > 1 && !bintree.Noop() {
						chain := new_chain(rules)
						rules = Linux_Rules{{chain: chain, goto_: true}}
					}
					cache[subtree] = rules
				}

				// Don't use "goto", if some tests for sub-nodes of
				// subtree are following.
				if len(seq) != 0 || !bintree.Noop() {
					for _, rule := range rules {

						// Create a copy of each rule because we must not change
						// the original cached rules.
						new_rule := *rule
						if len(seq) != 0 {
							new_rule.goto_ = false
						}
						if !bintree.Noop() {
							setter(&new_rule, bintree)
						}
						new_rules = append(new_rules, &new_rule)
					}
				} else {
					new_rules = append(new_rules, rules...)
				}
			}
			if seq == nil {
				break
			}

			// Take this value in next iteration.
			last := len(seq) - 1
			bintree, seq = seq[last], seq[:last]

			// Process remaining elements.
			for _, node := range seq {
				rules := gen_chain(node, order, depth)
				new_rules = append(new_rules, rules...)
			}
		}
		if len(new_rules) > 1 && !tree.Noop() {

			// Generate new chain. All elements of @seq are
			// known to be disjoint. If one element has matched
			// and branched to a chain, then the other elements
			// need not be tested again. This is implemented by
			// calling the chain using '-g' instead of the usual '-j'.
			chain := new_chain(new_rules)
			new_rule := &Linux_Rule{chain: chain, goto_: true}
			setter(new_rule, tree)
			return Linux_Rules{new_rule}
		} else {
			return new_rules
		}
	}

	// Build rule trees. Generate and process separate tree for
	// adjacent rules with same 'deny' attribute.
	// Store rule tree together with order of attributes.
	type tree_and_order struct {
		tree  *Lrule_tree
		order *Order
	}
	var rule_sets []tree_and_order
	var count [4]map[interface{}]int
	for i, _ := range count {
		count[i] = make(map[interface{}]int)
	}
	order := Order{
		{
			get: func(rule *Rule) interface{} { return rule.src_range },
			set: func(rule *Linux_Rule, val interface{}) {
				rule.src_range = val.(*Prt_bintree)
			},
			name: "src_range",
		},
		{
			get: func(rule *Rule) interface{} { return rule.dst },
			set: func(rule *Linux_Rule, val interface{}) {
				rule.dst = val.(*Net_bintree)
			},
			name: "dst",
		},
		{
			get: func(rule *Rule) interface{} { return rule.prt },
			set: func(rule *Linux_Rule, val interface{}) {
				rule.prt = val.(*Prt_bintree)
			},
			name: "prt",
		},
		{
			get: func(rule *Rule) interface{} { return rule.src },
			set: func(rule *Linux_Rule, val interface{}) {
				rule.src = val.(*Net_bintree)
			},
			name: "src",
		},
	}
	if len(rules) > 0 {
		prev_deny := rules[0].deny

		// Add special rule as marker, that end of rules has been reached.
		rules.push(&Rule{src: nil})
		var start int = 0
		last := len(rules) - 1
		var i int = 0
		for {
			rule := rules[i]
			deny := rule.deny
			if deny == prev_deny && i < last {

				// Count, which attribute has the largest number of
				// different values.
				for i, what := range order {
					count[i][what.get(rule)]++
				}
				i++
			} else {
				for i, attr_map := range count {
					order[i].count = len(attr_map)

					// Reset counter for next tree.
					count[i] = make(map[interface{}]int)
				}

				// Use key with smaller number of different values
				// first in rule tree. This gives smaller tree and
				// fewer tests in chains.
				sort.SliceStable(order[:], func(i, j int) bool {
					return order[i].count < order[j].count
				})
				rule_tree := make(Lrule_tree)
				for _, rule := range rules[start:i] {
					add := func(what int, tree *Lrule_tree) *Lrule_tree {
						key := order[what].get(rule)
						subtree := (*tree)[key]
						if subtree == nil {
							m := make(Lrule_tree)
							(*tree)[key] = &m
							subtree = &m
						}
						return subtree
					}
					subtree := add(0, &rule_tree)
					subtree = add(1, subtree)
					subtree = add(2, subtree)
					key3 := order[3].get(rule)
					if rule.deny {
						(*subtree)[key3] = coded_Ldeny
					} else {
						(*subtree)[key3] = coded_Lpermit
					}
				}

				//for _, what := range order {
				//   to_stderr(what.name)
				//}
				rule_sets = append(rule_sets, tree_and_order{&rule_tree, &order})
				if i == last {
					break
				}
				start = i
				prev_deny = deny
			}
		}
		rules = nil
	}

	var lrules Linux_Rules
	for i, set := range rule_sets {

		//    $print_tree->($tree, $order, 0);
		bintree := merge_subtrees(set.tree)
		result := gen_chain(bintree, set.order, 0)

		// Goto must not be used in last rule of rule tree which is
		// not the last tree.
		if i < len(rule_sets)-1 {
			rule := result[len(result)-1]
			rule.goto_ = false
		}

		// Postprocess lrules: Add missing attributes prt, src, dst
		// with no-op values.
		for _, rule := range result {
			if rule.src == nil {
				rule.src = &Net_bintree{IP_Net: *network_00}
			}
			if rule.dst == nil {
				rule.dst = &Net_bintree{IP_Net: *network_00}
			}
			prt := rule.prt
			src_range := rule.src_range
			if prt == nil && src_range == nil {
				rule.prt = &Prt_bintree{Proto: *prt_ip}
			} else if prt == nil {
				switch src_range.proto {
				case "tcp":
					rule.prt = &Prt_bintree{Proto: *prt_tcp}
				case "udp":
					rule.prt = &Prt_bintree{Proto: *prt_udp}
				case "icmp":
					rule.prt = &Prt_bintree{Proto: *prt_icmp}
				default:
					rule.prt = &Prt_bintree{Proto: *prt_ip}
				}
			}
		}
		lrules = append(lrules, result...)
	}
	acl_info.lrules = lrules
}

// Given an IP and mask, return its address
// as "x.x.x.x/x" or "x.x.x.x" if prefix == 32 (128 for IPv6).
func prefix_code(ip_net *IP_Net) string {
	size, bits := ip_net.Mask.Size()
	if size == bits {
		return ip_net.IP.String()
	} else {
		return ip_net.String()
	}
}

func action_code(rule *Linux_Rule) (result string) {
	if rule.chain != nil {
		result = rule.chain.name
	} else if rule.deny {
		result = "droplog"
	} else {
		result = "ACCEPT"
	}
	return
}

// Print chains of iptables.
// Objects have already been normalized to ip/mask pairs.
// NAT has already been applied.
func print_chains(fd *os.File, router_data *Router_Data) {
	chains := router_data.chains
	router_data.chains = nil
	if len(chains) == 0 {
		return
	}

	acl_info := router_data.acls[0]
	prt2obj := acl_info.prt2obj
	prt_ip := prt2obj["ip"]
	prt_icmp := prt2obj["icmp"]
	prt_tcp := prt2obj["tcp 1 65535"]
	prt_udp := prt2obj["udp 1 65535"]

	// Declare chain names.
	for _, chain := range chains {
		fmt.Fprintf(fd, ":%s -\n", chain.name)
	}

	// Define chains.
	for _, chain := range chains {
		prefix := fmt.Sprintf("-A %s", chain.name)
		for _, rule := range chain.rules {
			var jump string
			if rule.goto_ {
				jump = "-g"
			} else {
				jump = "-j"
			}
			result := fmt.Sprintf("%s %s", jump, action_code(rule))
			if src := rule.src; src != nil {
				if size, _ := src.Mask.Size(); size != 0 {
					result += " -s " + prefix_code(&src.IP_Net)
				}
			}
			if dst := rule.dst; dst != nil {
				if size, _ := dst.Mask.Size(); size != 0 {
					result += " -d " + prefix_code(&dst.IP_Net)
				}
			}
			src_range := rule.src_range
			prt := rule.prt
			switch {
			case src_range == nil && prt == nil:
				// break
			case prt != nil && prt.Proto.proto == "ip":
				// break
			case prt == nil:
				if src_range.Proto.proto == "ip" {
					break
				}
				prt = new(Prt_bintree)
				switch src_range.Proto.proto {
				case "tcp":
					prt.Proto = *prt_tcp
				case "udp":
					prt.Proto = *prt_udp
				case "icmp":
					prt.Proto = *prt_icmp
				default:
					prt.Proto = *prt_ip
				}
				fallthrough
			default:
				result += " " + iptables_prt_code(src_range, prt)
			}
			fmt.Fprintln(fd, prefix, result)
		}
	}

	// Empty line as delimiter.
	fmt.Fprintln(fd)
}

func iptables_acl_line(fd *os.File, rule *Linux_Rule, prefix string) {
	src, dst, src_range, prt := rule.src, rule.dst, rule.src_range, rule.prt
	var jump string
	if rule.goto_ {
		jump = "-g"
	} else {
		jump = "-j"
	}
	result := fmt.Sprintf("%s %s %s", prefix, jump, action_code(rule))
	if size, _ := src.Mask.Size(); size != 0 {
		result += " -s " + prefix_code(&src.IP_Net)
	}
	if size, _ := dst.Mask.Size(); size != 0 {
		result += " -d " + prefix_code(&dst.IP_Net)
	}
	if prt.proto != "ip" {
		result += " " + iptables_prt_code(src_range, prt)
	}
	fmt.Fprintln(fd, result)
}

func print_iptables_acl(fd *os.File, acl_info *ACL_Info) {
	name := acl_info.name
	fmt.Fprintf(fd, ":%s -\n", name)
	intf_prefix := fmt.Sprintf("-A %s", name)
	for _, rule := range acl_info.lrules {
		iptables_acl_line(fd, rule, intf_prefix)
	}
}

func convert_rule_objects(rules []*jRule, ip_net2obj Name2IP_Net, prt2obj Name2Proto) (Rules, bool) {
	if rules == nil {
		return nil, false
	}
	var expanded Rules
	var has_log bool
	for _, rule := range rules {
		src_list := ip_net_list(rule.Src, ip_net2obj)
		dst_list := ip_net_list(rule.Dst, ip_net2obj)
		prt_list := prt_list(rule.Prt, prt2obj)
		var src_range *Proto
		if rule.Src_range != "" {
			src_range = prt(rule.Src_range, prt2obj)
		}
		has_log = has_log || rule.Log != ""
		for _, src := range src_list {
			for _, dst := range dst_list {
				for _, prt := range prt_list {
					expanded.push(
						&Rule{
							deny:          rule.Deny == 1,
							src:           src,
							dst:           dst,
							src_range:     src_range,
							prt:           prt,
							log:           rule.Log,
							opt_secondary: rule.Opt_secondary == 1,
						})
				}
			}
		}
	}
	return expanded, has_log
}

type Router_Data struct {
	model             string
	acls              []*ACL_Info
	log_deny          string
	filter_only_group *IP_Net
	do_objectgroup    bool
	obj_groups_hash   map[group_key][]*Obj_Group
	obj_group_counter int
	chain_counter     int
	chains            []*Chain
}

func ip_net_list(names []string, ip_net2obj Name2IP_Net) []*IP_Net {
	result := make([]*IP_Net, len(names))
	for i, name := range names {
		obj, ok := ip_net2obj[name]
		if !ok {
			obj = create_ip_obj(name)
			ip_net2obj[name] = obj
		}
		result[i] = obj
	}
	return result
}

func prt(name string, prt2obj Name2Proto) *Proto {
	obj, ok := prt2obj[name]
	if !ok {
		obj = create_prt_obj(name)
		prt2obj[name] = obj
	}
	return obj
}

func prt_list(names []string, prt2obj Name2Proto) []*Proto {
	result := make([]*Proto, len(names))
	for i, name := range names {
		result[i] = prt(name, prt2obj)
	}
	return result
}

//go:generate easyjson Pass2.go
//easyjson:json
type jRouter_Data struct {
	Model          string      `json:"model"`
	Acls           []jACL_Info `json:"acls"`
	Filter_only    []string    `json:"filter_only"`
	Do_objectgroup int         `json:"do_objectgroup"`
	Log_deny       string      `json:"log_deny"`
}
type jACL_Info struct {
	Name           string   `json:"name"`
	Is_std_acl     int      `json:"is_std_acl"`
	Intf_rules     []*jRule `json:"intf_rules"`
	Rules          []*jRule `json:"rules"`
	Opt_networks   []string `json:"opt_networks"`
	No_opt_addrs   []string `json:"no_opt_addrs"`
	Need_protect   []string `json:"need_protect"`
	Filter_any_src int      `json:"filter_any_src"`
	Is_crypto_acl  int      `json:"is_crypto_acl"`
	Add_permit     int      `json:"add_permit"`
	Add_deny       int      `json:"add_deny"`
}
type jRule struct {
	Deny          int      `json:"deny"`
	Src           []string `json:"src"`
	Dst           []string `json:"dst"`
	Prt           []string `json:"prt"`
	Src_range     string   `json:"src_range"`
	Log           string   `json:"log"`
	Opt_secondary int      `json:"opt_secondary"`
}

func prepare_acls(path string) *Router_Data {
	var jdata jRouter_Data
	router_data := new(Router_Data)
	data, err := ioutil.ReadFile(path)
	if err != nil {
		panic(err)
	}
	err = easyjson.Unmarshal(data, &jdata)
	if err != nil {
		panic(err)
	}
	re := regexp.MustCompile("/ipv6/[^/]+$")
	ipv6 := re.MatchString(path)
	model := jdata.Model
	router_data.model = model
	router_data.log_deny = jdata.Log_deny
	do_objectgroup := jdata.Do_objectgroup == 1
	router_data.do_objectgroup = do_objectgroup
	raw_acls := jdata.Acls
	acls := make([]*ACL_Info, len(raw_acls))
	for i, raw_info := range raw_acls {

		// Process networks and protocols of each interface individually,
		// because relation between networks may be changed by NAT.
		ip_net2obj := make(Name2IP_Net)
		prt2obj := make(Name2Proto)

		intf_rules, has_log1 := convert_rule_objects(
			raw_info.Intf_rules, ip_net2obj, prt2obj)
		rules, has_log2 := convert_rule_objects(
			raw_info.Rules, ip_net2obj, prt2obj)

		filter_only := ip_net_list(jdata.Filter_only, ip_net2obj)

		opt_networks := ip_net_list(raw_info.Opt_networks, ip_net2obj)
		for _, obj := range opt_networks {
			obj.opt_networks = obj
		}
		no_opt_addrs := ip_net_list(raw_info.No_opt_addrs, ip_net2obj)
		for _, obj := range no_opt_addrs {
			obj.no_opt_addrs = true
		}
		need_protect := ip_net_list(raw_info.Need_protect, ip_net2obj)
		for _, obj := range need_protect {
			obj.need_protect = true
		}
		setup_ip_net_relation(ip_net2obj, ipv6)

		acl_info := &ACL_Info{
			name:           raw_info.Name,
			is_std_acl:     raw_info.Is_std_acl == 1,
			intf_rules:     intf_rules,
			rules:          rules,
			prt2obj:        prt2obj,
			ip_net2obj:     ip_net2obj,
			filter_only:    filter_only,
			opt_networks:   opt_networks,
			no_opt_addrs:   no_opt_addrs,
			filter_any_src: raw_info.Filter_any_src == 1,
			need_protect:   need_protect,
			network_00:     ip_net2obj[get_net00_addr(ipv6)],
		}
		acls[i] = acl_info

		if len(need_protect) > 0 {
			mark_supernets_of_need_protect(need_protect)
		}
		if model == "Linux" {
			add_tcp_udp_icmp(prt2obj)
		}

		setup_prt_relation(prt2obj)
		acl_info.prt_ip = prt2obj["ip"]

		if model == "Linux" {
			find_chains(acl_info, router_data)
		} else {
			intf_rules = optimize_rules(intf_rules, acl_info)
			intf_rules = join_ranges(intf_rules, prt2obj)
			rules = optimize_rules(rules, acl_info)
			rules = join_ranges(rules, prt2obj)
			acl_info.intf_rules = move_rules_esp_ah(intf_rules, prt2obj, has_log1)
			acl_info.rules = move_rules_esp_ah(rules, prt2obj, has_log2)

			has_final_permit := check_final_permit(acl_info)
			add_permit := raw_info.Add_permit == 1
			add_deny := raw_info.Add_deny == 1
			add_protect_rules(acl_info, has_final_permit || add_permit)
			if do_objectgroup && raw_info.Is_crypto_acl != 1 {
				find_objectgroups(acl_info, router_data)
			}
			if len(filter_only) > 0 && !add_permit {
				add_local_deny_rules(acl_info, router_data)
			} else if !has_final_permit {
				add_final_permit_deny_rule(acl_info, add_deny, add_permit)
			}
		}
	}
	router_data.acls = acls
	return router_data
}

// Given IP or group object, return its address in Cisco syntax.
func cisco_acl_addr(obj *IP_Net, model string) string {

	// Object group.
	if obj.IPNet == nil {
		var keyword string
		if model == "NX-OS" {
			keyword = "addrgroup"
		} else {
			keyword = "object-group"
		}
		return keyword + " " + obj.name
	}

	prefix, bits := obj.Mask.Size()
	if prefix == 0 {
		if model == "ASA" {
			if bits == 32 {
				return "any4"
			} else {
				return "any6"
			}
		} else {
			return "any"
		}
	} else if model == "NX-OS" {
		return obj.name
	} else {
		ip := obj.IP
		ip_code := ip.String()
		if prefix == bits {
			return "host " + ip_code
		} else {
			mask := net.IP(obj.Mask)

			// Inverse mask bits.
			// Must not inverse original mask, shared by multiple rules.
			if model == "NX-OS" || model == "IOS" {
				copy := make([]byte, len(mask))
				for i, byte := range mask {
					copy[i] = ^byte
				}
				mask = copy
			}
			mask_code := mask.String()
			return ip_code + " " + mask_code
		}
	}
}

func print_object_groups(fd *os.File, acl_info *ACL_Info, model string) {
	groups := acl_info.object_groups
	if len(groups) == 0 {
		return
	}
	var keyword string
	if model == "NX-OS" {
		keyword = "object-group ip address"
	} else {
		keyword = "object-group network"
	}
	for _, group := range groups {
		numbered := 10
		fmt.Fprintln(fd, keyword, group.name)
		for _, element := range group.elements {

			// Reject network with mask = 0 in group.
			// This occurs if optimization didn't work correctly.
			if size, _ := element.Mask.Size(); size == 0 {
				fatal_err("Unexpected network with mask 0 in object-group")
			}
			adr := cisco_acl_addr(element, model)
			if model == "NX-OS" {
				fmt.Fprintln(fd, "", numbered, adr)
				numbered += 10
			} else {
				fmt.Fprintln(fd, " network-object", adr)
			}
		}
	}
}

// Returns 3 values for building a Cisco ACL:
// permit <val1> <src> <val2> <dst> <val3>
func cisco_prt_code(src_range, prt *Proto) (t1, t2, t3 string) {
	proto := prt.proto

	switch proto {
	case "ip":
		return "ip", "", ""
	case "tcp", "udp":
		port_code := func(range_obj *Proto) string {
			ports := range_obj.ports
			v1, v2 := ports[0], ports[1]
			if v1 == v2 {
				return fmt.Sprint("eq ", v1)
			} else if v1 == 1 && v2 == 65535 {
				return ""
			} else if v2 == 65535 {
				return fmt.Sprint("gt ", v1-1)
			} else if v1 == 1 {
				return fmt.Sprint("lt ", v2+1)
			} else {
				return fmt.Sprint("range ", v1, v2)
			}
		}
		dst_prt := port_code(prt)
		if prt.established {
			if dst_prt != "" {
				dst_prt += " established"
			} else {
				dst_prt = "established"
			}
		}
		var src_prt string
		if src_range != nil {
			src_prt = port_code(src_range)
		}
		return proto, src_prt, dst_prt
	case "icmp":
		type_ := prt.type_
		if type_ != -1 {
			code := prt.code
			if code != -1 {
				return proto, "", fmt.Sprint(type_, code)
			} else {
				return proto, "", fmt.Sprint(type_)
			}
		} else {
			return proto, "", ""
		}
	default:
		return proto, "", ""
	}
}

func get_cisco_action(deny bool) string {
	if deny {
		return "deny"
	} else {
		return "permit"
	}
}

func print_asa_std_acl(fd *os.File, acl_info *ACL_Info, model string) {
	for _, rule := range acl_info.rules {
		fmt.Fprintln(
			fd,
			"access-list",
			acl_info.name,
			"standard",
			get_cisco_action(rule.deny),
			cisco_acl_addr(rule.src, model))
	}
}

func print_cisco_acl(fd *os.File, acl_info *ACL_Info, router_data *Router_Data) {
	model := router_data.model

	if acl_info.is_std_acl {
		print_asa_std_acl(fd, acl_info, model)
		return
	}

	name := acl_info.name
	numbered := 10
	prefix := ""
	switch model {
	case "IOS":
		fmt.Fprintln(fd, "ip access-list extended", name)
	case "NX-OS":
		fmt.Fprintln(fd, "ip access-list", name)
	case "ASA":
		prefix = "access-list " + name + " extended"
	}

	for _, rules := range []Rules{acl_info.intf_rules, acl_info.rules} {
		for _, rule := range rules {
			action := get_cisco_action(rule.deny)
			proto_code, src_port_code, dst_port_code :=
				cisco_prt_code(rule.src_range, rule.prt)
			result := fmt.Sprintf("%s %s %s", prefix, action, proto_code)
			result += " " + cisco_acl_addr(rule.src, model)
			if src_port_code != "" {
				result += " " + src_port_code
			}
			result += " " + cisco_acl_addr(rule.dst, model)
			if dst_port_code != "" {
				result += " " + dst_port_code
			}

			if rule.log != "" {
				result += " " + rule.log
			} else if rule.deny && router_data.log_deny != "" {
				result += " " + router_data.log_deny
			}

			// Add line numbers.
			if model == "NX-OS" {
				result = fmt.Sprintf(" %d%s", numbered, result)
				numbered += 10
			}
			fmt.Fprintln(fd, result)
		}
	}
}

func print_acl(fd *os.File, acl_info *ACL_Info, router_data *Router_Data) {
	model := router_data.model
	if model == "Linux" {

		// Print all sub-chains at once before first toplevel chain is printed.
		print_chains(fd, router_data)
		print_iptables_acl(fd, acl_info)
	} else {
		print_object_groups(fd, acl_info, model)
		print_cisco_acl(fd, acl_info, router_data)
	}
}

func print_combined(config []string, router_data *Router_Data, out_path string) {
	fd, err := os.Create(out_path)
	if err != nil {
		fatal_err("Can't open %s for writing: %v", out_path, err)
	}
	acl_hash := make(map[string]*ACL_Info)
	for _, acl := range router_data.acls {
		acl_hash[acl.name] = acl
	}

	// Print config and insert printed ACLs at "#insert <name>" markers.
	re := regexp.MustCompile("^#insert (.*)$")
	for _, line := range config {

		indexes := re.FindStringSubmatchIndex(line)

		if indexes != nil {
			// Print ACL.
			name := line[indexes[2]:indexes[3]]
			acl_info, found := acl_hash[name]
			if !found {
				fatal_err("Unexpected ACL %s", name)
			}
			print_acl(fd, acl_info, router_data)
		} else {
			// Print unchanged config line.
			fmt.Fprintln(fd, line)
		}
	}

	if err := fd.Close(); err != nil {
		fatal_err("Can't close %s: %v", out_path, err)
	}
}

func isDir(path string) bool {
	stat, err := os.Stat(path)
	return err == nil && stat.Mode().IsDir()
}

func isRegular(path string) bool {
	stat, err := os.Stat(path)
	return err == nil && stat.Mode().IsRegular()
}

// Try to use pass2 file from previous run.
// If identical files with extension .config and .rules
// exist in directory .prev/, then use copy.
func try_prev(device_path, dir, prev string) bool {
	if !isDir(prev) {
		return false
	}
	prev_file := prev + "/" + device_path
	if !isRegular(prev_file) {
		return false
	}
	code_file := dir + "/" + device_path
	for _, ext := range [...]string{"config", "rules"} {
		pass1name := code_file + "." + ext
		pass1prev := prev_file + "." + ext
		if !isRegular(pass1prev) {
			return false
		}
		cmd := exec.Command("cmp", "-s", pass1name, pass1prev)
		if cmd.Run() != nil {
			return false
		}
	}
	cmd := exec.Command("cp", "-p", prev_file, code_file)
	if cmd.Run() != nil {
		return false
	}

	// File was found and copied successfully.
	diag_msg("Reused .prev/" + device_path)
	return true
}

func read_file_lines(filename string) []string {
	fd, err := os.Open(filename)
	if err != nil {
		fatal_err("Can't open %s for reading: %v", filename, err)
	}
	result := make([]string, 0)
	scanner := bufio.NewScanner(fd)
	for scanner.Scan() {
		line := scanner.Text()
		result = append(result, line)
	}
	if err := scanner.Err(); err != nil {
		fatal_err("While reading device names: %v", err)
	}
	return result
}

func pass2_file(device_path, dir string, c chan bool) {
	success := false

	// Send ok on success
	defer func() { c <- success }()

	file := dir + "/" + device_path
	router_data := prepare_acls(file + ".rules")
	config := read_file_lines(file + ".config")
	print_combined(config, router_data, file)
	success = true
}

func apply_concurrent(device_names_fh *os.File, dir, prev string) {

	var started, generated, reused, errors int
	concurrent := config.concurrent
	c := make(chan bool, concurrent)
	workers_left := concurrent

	wait_and_check := func() {
		if <-c {
			generated++
		} else {
			errors++
		}
		started--
	}

	// Read to be processed files line by line.
	scanner := bufio.NewScanner(device_names_fh)
	for scanner.Scan() {
		device_path := scanner.Text()

		if try_prev(device_path, dir, prev) {
			reused++
		} else if 1 >= concurrent {
			// Process sequentially.
			pass2_file(device_path, dir, c)
			wait_and_check()
		} else if workers_left > 0 {
			// Start concurrent jobs at beginning.
			go pass2_file(device_path, dir, c)
			workers_left--
			started++
		} else {
			// Start next job, after some job has finished.
			wait_and_check()
			go pass2_file(device_path, dir, c)
			started++
		}
	}

	// Wait for all jobs to be finished.
	for started > 0 {
		wait_and_check()
	}

	if err := scanner.Err(); err != nil {
		fatal_err("While reading device names: %v", err)
	}

	if errors > 0 {
		fatal_err("Failed")
	}
	if generated > 0 {
		info("Generated files for %d devices", generated)
	}
	if reused > 0 {
		info("Reused %d files from previous run", reused)
	}
}

func pass2(dir string) {
	prev := dir + "/.prev"

	// Read to be processed files either from STDIN or from file.
	var from_pass1 *os.File
	if config.pipe {
		from_pass1 = os.Stdin
	} else {
		devlist := dir + "/.devlist"
		var err error
		from_pass1, err = os.Open(devlist)
		if err != nil {
			fatal_err("Can't open %s for reading: %v", devlist, err)
		}
	}

	apply_concurrent(from_pass1, dir, prev)

	// Remove directory '.prev' created by pass1
	// or remove symlink '.prev' created by newpolicy.pl.
	err := os.RemoveAll(prev)
	if err != nil {
		fatal_err("Can't remove %s: %v", prev, err)
	}
}

func main() {
	if len(os.Args) != 2 {
		fatal_err("Usage: %s DIR", os.Args[0])
	}
	var dir = os.Args[1]
	pass2(dir)
	info("Finished")
}
