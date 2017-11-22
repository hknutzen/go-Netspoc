package main

/*
Pass 2 of Netspoc - A Network Security Policy Compiler

(C) 2017 by Heinz Knutzen <heinz.knutzen@googlemail.com>

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
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type Config struct {
	concurrent int
	pipe bool
}

var (
	zero_ip = net.ParseIP("0.0.0.0")
	max_ip  = net.ParseIP("255.255.255.255")
	show_diag = false
	config = Config{concurrent: 2, pipe: false}
)

func to_sterr(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format, args...)
	fmt.Fprintln(os.Stderr)
}

func fatal_err (format string, args ...interface{}) {
	string := "Error: " + fmt.Sprintf(format, args...)
	fmt.Fprintln(os.Stderr, string)
	os.Exit(1)
}

func info (format string, args ...interface{}) {
	string := fmt.Sprintf(format, args...)
	fmt.Fprintln(os.Stderr, string)
}

func diag_msg (msg string) {
	if show_diag {
		fmt.Fprintln(os.Stderr, "DIAG: " + msg)
	}
}

type IP_Net struct {
	net *net.IPNet
	opt_networks *IP_Net
	no_opt_addrs, need_protect bool
	name string
	up *IP_Net
	is_supernet_of_need_protect map[*IP_Net]bool
}
type Proto struct {
	proto string
	ports [2]int
	established bool
	type_, code int
	name string
	up *Proto
	has_neighbor bool
}
type Name2IP_Net map[string]*IP_Net
type Name2Proto map[string]*Proto

func create_ip_obj (ip_net string) (*IP_Net) {
	_, net, _ := net.ParseCIDR(ip_net)
	return &IP_Net{ net: net, name: ip_net }
}

func get_ip_obj (ip net.IP, mask net.IPMask, ip_net2obj Name2IP_Net) (*IP_Net) {
	prefix, _ := mask.Size()
	name := fmt.Sprintf("%s/%d", ip.String(), prefix)
	obj, ok := ip_net2obj[name];
	if !ok {
		obj = &IP_Net{ net: &net.IPNet{ IP: ip, Mask: mask }, name: name }
		ip_net2obj[name] = obj
	}
	return obj
}

func create_prt_obj (descr string) (*Proto) {
	splice := strings.Split(descr, " ")
	proto := splice[0]
	prt := Proto{ proto: proto, name: descr }
    
	if proto == "tcp" || proto == "udp" {
		p1, _ := strconv.Atoi(splice[1])
		p2, _ := strconv.Atoi(splice[2])
		prt.ports = [...]int{ p1, p2 }
		if len(splice) > 3 {
			 prt.established = true
		}
	} else if proto == "icmp" {
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

type ByMask []net.IPMask

func (s ByMask) Len() int {
    return len(s)
}
func (s ByMask) Swap(i, j int) {
    s[i], s[j] = s[j], s[i]
}
func (s ByMask) Less(i, j int) bool {
    return bytes.Compare(s[i], s[j]) < 0
}

func setup_ip_net_relation (ip_net2obj Name2IP_Net) {
	if _, ok := ip_net2obj["0.0.0.0/0"]; !ok {
		ip_net2obj["0.0.0.0/0"] = create_ip_obj("0.0.0.0/0")
	}
	mask_ip_hash := make(map[string]map[string]*IP_Net)

	// Collect networks into mask_ip_hash.
	for _, network := range ip_net2obj {
		ip, mask := network.net.IP, network.net.Mask
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
	for k := range mask_ip_hash { mask_list = append(mask_list, net.IPMask(k)) }
	sort.Sort(sort.Reverse(ByMask(mask_list)))
	for i, mask := range mask_list {
		upper_masks := mask_list[i+1:]

		// No supernets available
		if len(upper_masks) == 0 { break }
        
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
	sort.Sort((ByMask(mask_list)))
	for _, mask := range mask_list {
		for _, network := range mask_ip_hash[string(mask)] {
			up := network.up
			if up == nil { continue }
			if opt_networks := up.opt_networks; nil != opt_networks {
				network.opt_networks = opt_networks
			}
		}
	}
}

func mark_supernets_of_need_protect (need_protect []*IP_Net) {
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

/*
# Needed for model=Linux.
sub add_tcp_udp_icmp {
    my ($prt2obj) = @_;
    $prt2obj->{'tcp 1 65535'} ||= create_prt_obj('tcp 1 65535');
    $prt2obj->{'udp 1 65535'} ||= create_prt_obj('udp 1 65535');
    $prt2obj->{icmp} ||= create_prt_obj('icmp');
}
*/

// Set {up} relation from port range to the smallest port range which
// includes it.
// If no including range is found, link it with next larger protocol.
// Set attribute {has_neighbor} to range adjacent to upper port.
// Abort on overlapping ranges.
func order_ranges (proto string, prt2obj Name2Proto, up *Proto) {
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
			if i == len(ranges) { return 0 }
			b := ranges[i]
			ports := b.ports
			b1, b2 := ports[0], ports[1]

			// Neighbors
			// aaaabbbb
			if a2 + 1 == b1 {

				// Mark protocol as candidate for joining of port ranges during
				// optimization.
				a.has_neighbor = true
				b.has_neighbor = true

				// Mark other ranges having identical start port.
				j := i + 1
				for j < len(ranges) {
					c := ranges[j]
					c1 := c.ports[0]
					if a2 + 1 != c1 { break }
					c.has_neighbor = true;
					j++
				}                    
			}

			// Not related.
			// aaaa    bbbbb
			if a2 < b1 { return i }

			// a includes b.
			// aaaaaaa
			//  bbbbb
			if a2 >= b2 {
				b.up = a
				i = check_subrange(b, b1, b2, i + 1)

				// Stop at end of array.
				if i == 0 { return 0 }
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

	if len(ranges) == 0 { return }
	index := 0
	for {
		a := ranges[index]
		a.up = up
		ports := a.ports
		a1, a2 := ports[0], ports[1]
		index++
		index = check_subrange(a, a1, a2, index)
		if index == 0 { break }
    }
    return;
}

func setup_prt_relation (prt2obj Name2Proto) {
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
	
	order_ranges("tcp", prt2obj, prt_ip);
	order_ranges("udp", prt2obj, prt_ip);

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

// Build rule tree from nested hash maps.
// Leaf nodes have rules as values.
type Rule_tree1 map[*Proto]*Expanded_Rule
type Rule_tree2 map[*IP_Net]Rule_tree1
type Rule_tree3 map[*IP_Net]Rule_tree2
type Rule_tree4 map[*Proto]Rule_tree3
type Rule_tree  map[bool]Rule_tree4

// Dynamically typed function adds next nesting level.
// Hash map for subtree is created if necessary.
func get_subtree(tree interface{}, key interface{}) interface{} {
	t := reflect.ValueOf(tree)
	k := reflect.ValueOf(key)
	s := t.MapIndex(k)
	// Create new map if necessary.
	if !s.IsValid() {
		s = reflect.MakeMap(t.Type().Elem())
		t.SetMapIndex(k, s)
	}
	return s.Interface()
}

func optimize_redundant_rules (cmp_hash, chg_hash Rule_tree) bool { 
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
														if chg_rule.deleted { continue; }
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
															if prt == nil { break }
														}
													}
												}
												dst = dst.up
												if dst == nil { break }
											}
										}
									}
									src = src.up
									if src == nil { break }
								}
							}
						}
						src_range = src_range.up
						if src_range == nil { break }
					}
				}
			}
			if deny { break }
			deny = true
		}
	}
	return changed
}

func optimize_rules (rules Rules, acl_info ACL_Info) Rules {
    prt_ip := acl_info.prt2obj["ip"]
    
	// For comparing redundant rules.
	rule_tree := make(Rule_tree)

	// Fill rule tree.
	changed := false
	for _, rule := range rules {
		src_range := rule.src_range
		if nil == src_range {
			src_range = prt_ip
		}
		
		// Dynamically typed operations.
		subtree := get_subtree(rule_tree, rule.deny)
		subtree  = get_subtree(subtree, src_range)
		subtree  = get_subtree(subtree, rule.src)
		
		// Go back to static type 'Rule_tree1'.
		subtree1 := get_subtree(subtree, rule.dst).(Rule_tree1)
		if _, found := subtree1[rule.prt]; found {
			rule.deleted = true
			changed = true
		} else {
			subtree1[rule.prt] = rule
		}
	}

	changed = optimize_redundant_rules (rule_tree, rule_tree) || changed
	
	// Implement rules as secondary rule, if possible.
	secondary_tree := make(Rule_tree)
	for _, rule := range rules {
		if !rule.opt_secondary { continue }
		if rule.deleted { continue }
		if rule.src.no_opt_addrs { continue }
		if rule.dst.no_opt_addrs { continue }
		src_range := rule.src_range
		if nil == src_range {
			src_range = prt_ip
		}

		// Replace obj by supernet.
		if nil != rule.src.opt_networks {
			rule.src = rule.src.opt_networks
		}
		if nil != rule.dst.opt_networks && !rule.dst.need_protect {
			rule.dst = rule.dst.opt_networks
		}

		// Change protocol to IP.
		rule.prt = prt_ip

		// Add new rule to secondary_tree. If multiple rules are
		// converted to the same secondary rule, only the first one
		// will be created.
		subtree := get_subtree(secondary_tree, rule.deny)
		subtree  = get_subtree(subtree, src_range)
		subtree  = get_subtree(subtree, rule.src)
		subtree1 := get_subtree(subtree, rule.dst).(Rule_tree1)
		if _, found := subtree1[rule.prt]; found {
			rule.deleted = true
			changed = true
		} else {
			subtree1[rule.prt] = rule
		}
	}

    if nil != secondary_tree {
		 changed =
			 optimize_redundant_rules(secondary_tree, secondary_tree) || changed
		 changed =
			 optimize_redundant_rules(secondary_tree, rule_tree) || changed
    }

	if changed {
		new_rules := make(Rules, 0)
		for _, rule := range rules {
			if rule.deleted { continue }
			new_rules.push(rule)
		}
		rules = new_rules
    }
	return rules
}

// Join adjacent port ranges.
func join_ranges (rules Rules, prt2obj Name2Proto) Rules {
	type key struct {
		deny bool
		src, dst *IP_Net
		src_range *Proto
		log, proto string
	}
	changed := false
	rule_tree := make(map[key]*Rules)
	for _, rule := range rules {

		// Only ranges which have a neighbor may be successfully optimized.
		// Currently only dst_ranges are handled.
		if !rule.prt.has_neighbor { continue }

		k := key{
			rule.deny, rule.src, rule.dst, rule.src_range, rule.log,
			rule.prt.proto,
		}
		rule_tree[k].push(rule)
	}

	rule2range := make(map[*Expanded_Rule][2]int)
	rule2del := make(map[*Expanded_Rule]bool)
	for _, rules_ref := range rule_tree {
		sorted := *rules_ref

		// Nothing to do if only a single rule.
		if len(sorted) < 2 { continue }

		// Values of rules are rules with identical
		// deny/src/dst/src_range/log/TCP or UDP protocol type.

		// When sorting these rules by low port number, rules with
		// adjacent protocols will placed side by side. There can't be
		// overlaps, because they have been split in function
		// 'order_ranges'. There can't be sub-ranges, because they have
		// been deleted as redundant already.
		sort.Slice(sorted,  func(i, j int) bool {
			return sorted[i].prt.ports[0] < sorted[j].prt.ports[0]
		})
		i      := 0
		rule_a := sorted[i]
		a1, a2 := rule_a.prt.ports[0], rule_a.prt.ports[1]
		i++
		for ; i < len(sorted) ; i++ {
			rule_b := sorted[i]
			b1, b2 := rule_b.prt.ports[0], rule_b.prt.ports[1]

			// Found adjacent port ranges.
			if a2 + 1 == b1 {
                                
				// Extend range of previous two or more elements.
				if ports,ok := rule2range[rule_a]; ok {
                                    
					ports[1] = b2
					rule2range[rule_b] = ports
					delete(rule2range, rule_a)
				} else {
                                    
					// Combine ranges of $rule_a and $rule_b.
					rule2range[rule_b] = [...]int{ a1, b2 }
				}
                                
				// Mark previous rule as deleted.
				rule2del[rule_a] = true
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
			if rule2del[rule] { continue }

			// Process rules with joined port ranges.
			if ports, ok := rule2range[rule]; ok {
				proto := rule.prt.proto
				key   := fmt.Sprintf("%s %i %i", proto, ports[0], ports[1])

				// Try to find existing prt with matching range.
				// This is needed for find_objectgroups to work.
				new_prt, ok := prt2obj[key]
				if !ok {
					new_prt = &Proto{ proto: proto, ports: ports }
					prt2obj[key] = new_prt
				}
				new_rule := *rule
				new_rule.prt = new_prt
				new_rules.push(&new_rule)
			} else {
				new_rules.push(rule)
			}
		}
		rules = new_rules
    }
    return rules
}

type Expanded_Rule struct {
	deny bool
	src, dst *IP_Net
	prt, src_range	*Proto
	log string
	deleted bool
	opt_secondary bool
}

type ACL_Info struct {
	name string
	is_std_acl bool
	intf_rules, rules Rules
	prt2obj Name2Proto
	ip_net2obj Name2IP_Net
	filter_only, opt_networks, no_opt_addrs, need_protect []*IP_Net
	filter_any_src bool
	network_00 *IP_Net
	prt_ip *Proto
	object_groups []*Obj_Group
}

type Rules []*Expanded_Rule
func (rules *Rules) push(rule *Expanded_Rule) {
	*rules = append(*rules, rule)
}
	
// Protocols ESP and AH are be placed first in Cisco ACL
// for performance reasons.
// These rules need to have a fixed order.
// Otherwise the connection may be lost,
// - if the device is accessed over an IPSec tunnel
// - and we change the ACL incrementally.
func move_rules_esp_ah (rules Rules, prt2obj Name2Proto) Rules {
	prt_esp := prt2obj["50"]
	prt_ah  := prt2obj["51"]
	if prt_esp == nil && prt_ah == nil {  return rules }
	if rules == nil { return nil }
	var deny_rules, crypto_rules, permit_rules Rules
	for _, rule := range rules {
		if rule.deny {
			deny_rules.push(rule)
		} else if rule.prt == prt_esp || rule.prt == prt_ah {
			crypto_rules.push(rule)
		} else {
			permit_rules.push(rule)
		}
	}
	
	// Sort crypto rules.
	sort.Slice(crypto_rules, func(i, j int) bool {
		switch strings.Compare(
			crypto_rules[i].prt.proto,
			crypto_rules[j].prt.proto) {
			case -1: return true
			case 1: return false
			}
		s_a := crypto_rules[i].src
		s_b := crypto_rules[j].src
		switch bytes.Compare(s_a.net.IP, s_b.net.IP) {
		case -1: return true
		case 1: return false
		}
		switch bytes.Compare(net.IP(s_a.net.Mask), net.IP(s_b.net.Mask)) {
		case -1: return true
		case 1: return false
		}
		d_a := crypto_rules[i].dst
		d_b := crypto_rules[j].dst
		switch bytes.Compare(d_a.net.IP, d_b.net.IP) {
		case -1: return true
		case 1: return false
		}
		return -1 == bytes.Compare(net.IP(d_a.net.Mask), net.IP(d_b.net.Mask))
	})
	return append(deny_rules, append(crypto_rules, permit_rules...)...)
}

func create_group (elements []*IP_Net, acl_info *ACL_Info, router_data *Router_Data) *Obj_Group{
	name := fmt.Sprintf("g%d", router_data.obj_group_counter)
	group_ref := &IP_Net{ net: nil, name: name }
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
func add_local_deny_rules (acl_info *ACL_Info, router_data *Router_Data) {
	network_00, prt_ip := acl_info.network_00, acl_info.prt_ip
	filter_only := acl_info.filter_only
	var src_networks []*IP_Net
	if acl_info.filter_any_src {
		src_networks = []*IP_Net{network_00}
	} else {
		src_networks = filter_only
	}
	
	if router_data.do_objectgroup {
		group_or_single := func (obj_list []*IP_Net) *IP_Net {
			if 1 == len(obj_list) {
				return obj_list[0]
			} else if nil != router_data.filter_only_group {

				// Reuse object-group at all interfaces.
				return router_data.filter_only_group
			} else {
				group := create_group(obj_list, acl_info, router_data)
				router_data.filter_only_group = group.ref
				return group.ref
			}
		}
		acl_info.rules.push(
			&Expanded_Rule{
				deny: true,
				src:  group_or_single(src_networks), 
				dst:  group_or_single(filter_only), 
				prt:  prt_ip,
			})
	} else {
		for _, src := range src_networks {
			for _, dst := range filter_only {
				acl_info.rules.push(
					&Expanded_Rule{ deny: true, src: src, dst: dst, prt: prt_ip })
			}
		}
	}
	acl_info.rules.push(
		&Expanded_Rule{ src: network_00, dst: network_00, prt: prt_ip })
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
func combine_adjacent_ip_mask (hash map[*IP_Net]*Expanded_Rule, ip_net2obj Name2IP_Net) []*IP_Net {

    // Take objects from keys of map.
    // Sort by mask. Adjacent networks will be adjacent elements then.
	elements := make([]*IP_Net, 0, len(hash))
	for element := range hash {
		elements = append(elements, element)
	}
	sort.Slice(elements, func(i, j int) bool {
		cmp := bytes.Compare(elements[i].net.IP, elements[j].net.IP)
		if cmp < 0 { return true }
		if cmp > 0 { return false }
		return bytes.Compare(elements[i].net.Mask, elements[j].net.Mask) < 0
	})

	// Find left and rigth part with identical mask and combine them
	// into next larger network.
	// Compare up to last but one element.
	for i := 0; i < len(elements) - 1 ; i++ {
		element1 := elements[i]
		element2 := elements[i+1]
		mask := element1.net.Mask
		if bytes.Compare(mask, element2.net.Mask) != 0 { continue }
		prefix, bits := mask.Size()
		prefix--
		up_mask := net.CIDRMask(prefix, bits)
		ip1 := element1.net.IP
		ip2 := element2.net.IP
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
		if i >= len(elements) - 1 { break }

		// Compare current network again.
		i--
    }
    return elements
}

const min_object_group_size = 2

type Obj_Group struct {
	name string
	elements []*IP_Net
	ref *IP_Net
	hash map[string]bool
}

// For searching efficiently for matching group.
type group_key struct {
	size int
	first string
}

func find_objectgroups (acl_info *ACL_Info, router_data *Router_Data) {
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
			deny bool
			that *IP_Net
			src_range, prt *Proto
			log string
		}
		group_rule_tree := make(map[key]map[*IP_Net]*Expanded_Rule)

		// Find groups of rules with identical
		// deny, src_range, prt, log, src/dst and different dst/src.
		for _, rule := range rules {
			deny      := rule.deny;
			src_range := rule.src_range
			prt       := rule.prt
			log       := rule.log
			this      := rule.src
			that      := rule.dst
			if this_is_dst {
				this, that = that, this
			}
			k := key{deny, that, src_range, prt, log}
			href, ok := group_rule_tree[k]
			if !ok {
				href = make(map[*IP_Net]*Expanded_Rule)
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
			hash map[*IP_Net]*Expanded_Rule
		}
		group_glue := make(map[*Expanded_Rule]*glue_type)
		for _, href := range group_rule_tree {

			// href is {dst/src => rule, ...}
			if len(href) < min_object_group_size { continue }

			glue := glue_type{ hash: href }

			// All this rules have identical deny, src_range, prt
			// and dst/src and shall be replaced by a single new
			// rule referencing an object group.
			for _, rule := range href {
				group_glue[rule] = &glue;
			}
		}
			
		// Find group with identical elements
		// or define a new one
		// or return combined network.
		// Returns IP_Net object with empty IP, representing a group.
		get_group := func (hash map[*IP_Net]*Expanded_Rule) *IP_Net {

			// Get sorted and combined list of objects from hash of objects.
			// Hash is adjusted, if objects are combined.
			elements := combine_adjacent_ip_mask(hash, ip_net2obj)
			size := len(elements)

			// If all elements have been combined into one single network,
			// don't create a group, but take single element as result.
			if 1 == size {
				return elements[0]
			}
			
			// Use size and first element as keys for efficient hashing.
			// Name of element is used, because elements are regenerated
			// between pricessing of different ACLs.
			first := elements[0]
			key := group_key{size, first.name}

			// Search group with identical elements.
			if groups, ok := key2group[key]; ok {
				HASH:			
				for _, group := range groups {
					href := group.hash
					
					// Check elements for equality.
					for key := range hash {
						if _, ok := href[key.name]; !ok { continue HASH }
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
				if glue.active { continue }
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

func add_protect_rules (acl_info *ACL_Info, has_final_permit bool) {
	need_protect := acl_info.need_protect
	if len(need_protect) == 0 { return }
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
		if rule.deny { continue }
		if rule.src != network_00 { continue }
		if rule.prt != prt_ip { continue }
		dst := rule.dst
		if dst.need_protect {
			no_protect[dst] = true
		}

		if has_final_permit {
			rules[i] = nil;
			deleted++
		}
	}
	if deleted != 0 {
		new_rules := make(Rules, 0, len(rules) - deleted)
		for _, rule := range rules {
			if rule != nil {
				new_rules = append(new_rules, rule)
			}
		}
		acl_info.intf_rules = new_rules
	}

	// Deny rule is needless if there is no such permit rule.
	// Try to optimize this case.
	protect_map := make(map[*IP_Net]bool)
	rules = acl_info.rules
	for _, rule := range rules {
		if rule.deny { continue }
		if rule.prt.established { continue }
		dst := rule.dst
		hash := dst.is_supernet_of_need_protect
		if hash == nil { continue }
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
			&Expanded_Rule{
				deny: true,
				src: network_00,
				dst: intf,
				prt: prt_ip,
			})
	}
}


// Check if last rule is 'permit ip any any'.
func check_final_permit (acl_info *ACL_Info) bool {
	rules := acl_info.rules
	l := len(rules)
	if l == 0 { return false }
	last := rules[l-1]
	return !last.deny &&
		last.src == acl_info.network_00 &&
		last.dst == acl_info.network_00 &&
		last.prt == acl_info.prt_ip
}

// Add 'deny|permit ip any any' at end of ACL.
func add_final_permit_deny_rule (acl_info *ACL_Info, add_deny, add_permit bool) {
	if add_deny || add_permit { 
		acl_info.rules.push(
			&Expanded_Rule{
				deny: add_deny,
				src: acl_info.network_00,
				dst: acl_info.network_00,
				prt: acl_info.prt_ip,
			})
	}
}

/*
# Returns iptables code for filtering a protocol.
sub iptables_prt_code {
    my ($src_range, $prt) = @_;
    my $proto = $prt->{proto};

    if ($proto eq 'tcp' or $proto eq 'udp') {
        my $port_code = sub {
            my ($range_obj) = @_;
            my ($v1, $v2) = @{ $range_obj->{range} };
            if ($v1 == $v2) {
                return $v1;
            }
            elsif ($v1 == 1 and $v2 == 65535) {
                return '';
            }
            elsif ($v2 == 65535) {
                return "$v1:";
            }
            elsif ($v1 == 1) {
                return ":$v2";
            }
            else {
                return "$v1:$v2";
            }
        };
        my $result = "-p $proto";
        my $sport = $src_range && $port_code->($src_range);
        $result .= " --sport $sport" if $sport;
        my $dport = $port_code->($prt);
        $result .= " --dport $dport" if $dport;
        return $result;
    }
    elsif ($proto eq 'icmp') {
        if (defined(my $type = $prt->{type})) {
            if (defined(my $code = $prt->{code})) {
                return "-p $proto --icmp-type $type/$code";
            }
            else {
                return "-p $proto --icmp-type $type";
            }
        }
        else {
            return "-p $proto";
        }
    }
    else {
        return "-p $proto";
    }
}


# Handle iptables.
#
#sub debug_bintree {
#    my ($tree, $depth) = @_;
#    $depth ||= '';
#    my $ip      = bitstr($tree->{ip});
#    my $mask    = mask2prefix($tree->{mask});
#    my $subtree = $tree->{subtree} ? 'subtree' : '';
#
#    debug($depth, " $ip/$mask $subtree");
#    debug_bintree($tree->{lo}, "${depth}l") if $tree->{lo};
#    debug_bintree($tree->{hi}, "${depth}h") if $tree->{hi};
#    return;
#}

# Nodes are reverse sorted before being added to bintree.
# Redundant nodes are discarded while inserting.
# A node with value of sub-tree S is discarded,
# if some parent node already has sub-tree S.
sub add_bintree;
sub add_bintree {
    my ($tree,    $node)      = @_;
    my ($tree_ip, $tree_mask) = @{$tree}{qw(ip mask)};
    my ($node_ip, $node_mask) = @{$node}{qw(ip mask)};
    my $result;

    # The case where new node is larger than root node will never
    # occur, because nodes are sorted before being added.

    if ($tree_mask lt $node_mask && match_ip($node_ip, $tree_ip, $tree_mask)) {

        # Optimization for this special case:
        # Root of tree has attribute {subtree} which is identical to
        # attribute {subtree} of current node.
        # Node is known to be less than root node.
        # Hence node together with its subtree can be discarded
        # because it is redundant compared to root node.
        # ToDo:
        # If this optimization had been done before merge_subtrees,
        # it could have merged more subtrees.
        if (   not $tree->{subtree}
            or not $node->{subtree}
            or $tree->{subtree} ne $node->{subtree})
        {
            my $prefix = mask2prefix($tree_mask);
            my $mask = prefix2mask($prefix+1);
            my $branch = match_ip($node_ip, $tree_ip, $mask) ? 'lo' : 'hi';
            if (my $subtree = $tree->{$branch}) {
                $tree->{$branch} = add_bintree $subtree, $node;
            }
            else {
                $tree->{$branch} = $node;
            }
        }
        $result = $tree;
    }

    # Create common root for tree and node.
    else {
        while (1) {
            my $prefix = mask2prefix($tree_mask);
            $tree_mask = prefix2mask($prefix-1);
            last if ($node_ip & $tree_mask) eq ($tree_ip & $tree_mask);
        }
        $result = {
            ip   => ($node_ip & $tree_mask),
            mask => $tree_mask
        };
        @{$result}{qw(lo hi)} =
          $node_ip lt $tree_ip ? ($node, $tree) : ($tree, $node);
    }

    # Merge adjacent sub-networks.
  MERGE:
    {
        $result->{subtree} and last;
        my $lo = $result->{lo} or last;
        my $hi = $result->{hi} or last;
        my $prefix = mask2prefix($result->{mask});
        my $mask = prefix2mask($prefix+1);
        $lo->{mask} eq $mask or last;
        $hi->{mask} eq $mask or last;
        $lo->{subtree} and $hi->{subtree} or last;
        $lo->{subtree} eq $hi->{subtree} or last;

        for my $key (qw(lo hi)) {
            $lo->{$key} and last MERGE;
            $hi->{$key} and last MERGE;
        }

#       debug('Merged: ', print_ip $lo->{ip},' ',
#             print_ip $hi->{ip},'/',print_ip $hi->{mask});
        $result->{subtree} = $lo->{subtree};
        delete $result->{lo};
        delete $result->{hi};
    }
    return $result;
}

# Build a binary tree for src/dst objects.
sub gen_addr_bintree {
    my ($elements, $tree) = @_;

    # Sort in reverse order by mask and then by IP.
    my @nodes =
      sort { $b->{mask} cmp $a->{mask} || $b->{ip} cmp $a->{ip} }
      map {
        my ($ip, $mask) = @{$_}{qw(ip mask)};

        # The tree's node is a simplified network object with
        # missing attribute 'name' and extra 'subtree'.
        { ip      => $ip,
          mask    => $mask,
          subtree => $tree->{$_->{name}}
        }
      } @$elements;
    my $bintree = pop @nodes;
    while (my $next = pop @nodes) {
        $bintree = add_bintree $bintree, $next;
    }

    # Add attribute {noop} to node which doesn't add any test to
    # generated rule.
    $bintree->{noop} = 1 if $bintree->{mask} eq $zero_ip;

#    debug_bintree($bintree);
    return $bintree;
}

# Build a tree for src-range/prt objects. Sub-trees for tcp and udp
# will be binary trees. Nodes have attributes {proto}, {range},
# {type}, {code} like protocols (but without {name}).
# Additional attributes for building the tree:
# For tcp and udp:
# {lo}, {hi} for sub-ranges of current node.
# For other protocols:
# {seq} an array of ordered nodes for sub protocols of current node.
# Elements of {lo} and {hi} or elements of {seq} are guaranteed to be
# disjoint.
# Additional attribute {subtree} is set with corresponding subtree of
# protocol object if current node comes from a rule and wasn't inserted
# for optimization.
sub gen_prt_bintree {
    my ($elements, $tree) = @_;

    my $ip_prt;
    my (%top_prt, %sub_prt);

    # Add all protocols directly below protocol 'ip' into hash %top_prt
    # grouped by protocol. Add protocols below top protocols or below
    # other protocols of current set of protocols to hash %sub_prt.
  PRT:
    for my $prt (@$elements) {
        my $proto = $prt->{proto};
        if ($proto eq 'ip') {
            $ip_prt = $prt;
            next PRT;
        }

        my $up = $prt->{up};

        # Check if $prt is sub protocol of any other protocol of
        # current set. But handle direct sub protocols of 'ip' as top
        # protocols.
        while ($up->{up}) {
            if (my $subtree = $tree->{$up->{name}}) {

                # Found sub protocol of current set.
                # Optimization:
                # Ignore the sub protocol if both protocols have
                # identical subtrees.
                # In this case we found a redundant sub protocol.
                if ($tree->{$prt->{name}} ne $subtree) {
                    push @{ $sub_prt{$up} }, $prt;
                }
                next PRT;
            }
            $up = $up->{up};
        }

        # Not a sub protocol (except possibly of IP).
        my $key = $proto =~ /^\d+$/ ? 'proto' : $proto;
        push @{ $top_prt{$key} }, $prt;
    }

    # Collect subtrees for tcp, udp, proto and icmp.
    my @seq;

# Build subtree of tcp and udp protocols.
    #
    # We need not to handle 'tcp established' because it is only used
    # for stateless routers, but iptables is stateful.
    my ($gen_lohitrees, $gen_rangetree);
    $gen_lohitrees = sub {
        my ($prt_aref) = @_;
        if (not $prt_aref) {
            return (undef, undef);
        }
        elsif (@$prt_aref == 1) {
            my $prt = $prt_aref->[0];
            my ($lo, $hi) = $gen_lohitrees->($sub_prt{$prt});
            my $node = {
                proto   => $prt->{proto},
                range   => $prt->{range},
                subtree => $tree->{$prt->{name}},
                lo      => $lo,
                hi      => $hi
            };
            return ($node, undef);
        }
        else {
            my @ranges =
              sort { $a->{range}->[0] <=> $b->{range}->[0] } @$prt_aref;

            # Split array in two halves.
            my $mid   = int($#ranges / 2);
            my $left  = [ @ranges[ 0 .. $mid ] ];
            my $right = [ @ranges[ $mid + 1 .. $#ranges ] ];
            return ($gen_rangetree->($left), $gen_rangetree->($right));
        }
    };
    $gen_rangetree = sub {
        my ($prt_aref) = @_;
        my ($lo, $hi) = $gen_lohitrees->($prt_aref);
        return $lo if not $hi;
        my $proto = $lo->{proto};

        # Take low port from lower tree and high port from high tree.
        my $range = [ $lo->{range}->[0], $hi->{range}->[1] ];

        # Merge adjacent port ranges.
        if (    $lo->{range}->[1] + 1 == $hi->{range}->[0]
            and $lo->{subtree}
            and $hi->{subtree}
            and $lo->{subtree} eq $hi->{subtree})
        {
            my @hilo =
              grep { defined $_ } $lo->{lo}, $lo->{hi}, $hi->{lo}, $hi->{hi};
            if (@hilo <= 2) {

#		debug("Merged: $lo->{range}->[0]-$lo->{range}->[1]",
#		      " $hi->{range}->[0]-$hi->{range}->[1]");
                my $node = {
                    proto   => $proto,
                    range   => $range,
                    subtree => $lo->{subtree}
                };
                $node->{lo} = shift @hilo if @hilo;
                $node->{hi} = shift @hilo if @hilo;
                return $node;
            }
        }
        return (
            {
                proto => $proto,
                range => $range,
                lo    => $lo,
                hi    => $hi
            }
        );
    };
    for my $what (qw(tcp udp)) {
        next if not $top_prt{$what};
        push @seq, $gen_rangetree->($top_prt{$what});
    }

# Add single nodes for numeric protocols.
    if (my $aref = $top_prt{proto}) {
        for my $prt (sort { $a->{proto} <=> $b->{proto} } @$aref) {
            my $node = { proto => $prt->{proto}, subtree => $tree->{$prt->{name}} };
            push @seq, $node;
        }
    }

# Build subtree of icmp protocols.
    if (my $icmp_aref = $top_prt{icmp}) {
        my %type2prt;
        my $icmp_any;

        # If one protocol is 'icmp any' it is the only top protocol,
        # all other icmp protocols are sub protocols.
        if (not defined $icmp_aref->[0]->{type}) {
            $icmp_any  = $icmp_aref->[0];
            $icmp_aref = $sub_prt{$icmp_any};
        }

        # Process icmp protocols having defined type and possibly defined code.
        # Group protocols by type.
        for my $prt (@$icmp_aref) {
            my $type = $prt->{type};
            push @{ $type2prt{$type} }, $prt;
        }

        # Parameter is array of icmp protocols all having
        # the same type and different but defined code.
        # Return reference to array of nodes sorted by code.
        my $gen_icmp_type_code_sorted = sub {
            my ($aref) = @_;
            [
                map {
                    {
                        proto   => 'icmp',
                        type    => $_->{type},
                        code    => $_->{code},
                        subtree => $tree->{$_->{name}}
                    }
                  }
                  sort { $a->{code} <=> $b->{code} } @$aref
            ];
        };

        # For collecting subtrees of icmp subtree.
        my @seq2;

        # Process grouped icmp protocols having the same type.
        for my $type (sort { $a <=> $b } keys %type2prt) {
            my $aref2 = $type2prt{$type};
            my $node2;

            # If there is more than one protocol,
            # all have same type and defined code.
            if (@$aref2 > 1) {
                my $seq3 = $gen_icmp_type_code_sorted->($aref2);

                # Add a node 'icmp type any' as root.
                $node2 = {
                    proto => 'icmp',
                    type  => $type,
                    seq   => $seq3,
                };
            }

            # One protocol 'icmp type any'.
            else {
                my $prt = $aref2->[0];
                $node2 = {
                    proto   => 'icmp',
                    type    => $type,
                    subtree => $tree->{$prt->{name}}
                };
                if (my $aref3 = $sub_prt{$prt}) {
                    $node2->{seq} = $gen_icmp_type_code_sorted->($aref3);
                }
            }
            push @seq2, $node2;
        }

        # Add root node for icmp subtree.
        my $node;
        if ($icmp_any) {
            $node = {
                proto   => 'icmp',
                seq     => \@seq2,
                subtree => $tree->{$icmp_any->{name}}
            };
        }
        elsif (@seq2 > 1) {
            $node = { proto => 'icmp', seq => \@seq2 };
        }
        else {
            $node = $seq2[0];
        }
        push @seq, $node;
    }

# Add root node for whole tree.
    my $bintree;
    if ($ip_prt) {
        $bintree = {
            proto   => 'ip',
            seq     => \@seq,
            subtree => $tree->{$ip_prt->{name}}
        };
    }
    elsif (@seq > 1) {
        $bintree = { proto => 'ip', seq => \@seq };
    }
    else {
        $bintree = $seq[0];
    }

    # Add attribute {noop} to node which doesn't need any test in
    # generated chain.
    $bintree->{noop} = 1 if $bintree->{proto} eq 'ip';
    return $bintree;
}

sub find_chains {
    my ($acl_info, $router_data) = @_;
    my $rules      = $acl_info->{rules};
    my $ip_net2obj = $acl_info->{ip_net2obj};
    my $prt2obj    = $acl_info->{prt2obj};
    my %ref_type = (
        src       => $ip_net2obj,
        dst       => $ip_net2obj,
        src_range => $prt2obj,
        prt       => $prt2obj,
    );

    my $prt_ip     = $prt2obj->{ip};
    my $prt_icmp   = $prt2obj->{icmp};
    my $prt_tcp    = $prt2obj->{'tcp 1 65535'};
    my $prt_udp    = $prt2obj->{'udp 1 65535'};
    my $network_00 = $ip_net2obj->{'0.0.0.0/0'};

    # For generating names of chains.
    # Initialize if called first time.
    $router_data->{chain_counter} ||= 1;

    # Set {action} attribute in $rule, so we can handle all properties
    # of a rule in unified manner.
    # Change {src_range} attribute.
    for my $rule (@$rules) {
        if (!$rule->{action}) {
            $rule->{action} = $rule->{deny} ? 'deny' : 'permit';
        }
        my $src_range = $rule->{src_range};
        if (not $src_range) {
            my $proto = $rule->{prt}->{proto};

            # Specify protocols tcp, udp, icmp in
            # {src_range}, to get more efficient chains.
            $src_range =
                $proto eq 'tcp'  ? $prt_tcp
              : $proto eq 'udp'  ? $prt_udp
              : $proto eq 'icmp' ? $prt_icmp
              :                    $prt_ip;
            $rule->{src_range} = $src_range;
        }
    }

    my %cache;

#    my $print_tree;
#    $print_tree = sub {
#        my ($tree, $order, $depth) = @_;
#        for my $name (keys %$tree) {
#
#            debug(' ' x $depth, $name);
#            if ($depth < $#$order) {
#                $print_tree->($tree->{$name}, $order, $depth + 1);
#            }
#        }
#    };

    my $insert_bintree = sub {
        my ($tree, $order, $depth) = @_;
        my $key      = $order->[$depth];
        my $ref2x    = $ref_type{$key};
        my @elements = map { $ref2x->{$_} } keys %$tree;

        # Put prt/src/dst objects at the root of some subtree into a
        # (binary) tree. This is used later to convert subsequent tests
        # for ip/mask or port ranges into more efficient nested chains.
        my $bintree;
        if ($ref2x eq $ip_net2obj) {
            $bintree = gen_addr_bintree(\@elements, $tree);
        }
        else {    # $ref2x eq $prt2obj
            $bintree = gen_prt_bintree(\@elements, $tree);
        }
        return $bintree;
    };

    # Used by $merge_subtrees1 to find identical subtrees.
    # Use hash for efficient lookup.
    my %depth2size2subtrees;
    my %subtree2bintree;

    # Find and merge identical subtrees.
    my $merge_subtrees1 = sub {
        my ($tree, $order, $depth) = @_;

      SUBTREE:
        for my $subtree (values %$tree) {
            my @keys = keys %$subtree;
            my $size = @keys;

            # Find subtree with identical keys and values;
          FIND:
            for my $subtree2 (@{ $depth2size2subtrees{$depth}->{$size} }) {
                for my $key (@keys) {
                    if (not $subtree2->{$key}
                        or $subtree2->{$key} ne $subtree->{$key})
                    {
                        next FIND;
                    }
                }

                # Substitute current subtree with found subtree.
                $subtree = $subtree2bintree{$subtree2};
                next SUBTREE;

            }

            # Found a new subtree.
            push @{ $depth2size2subtrees{$depth}->{$size} }, $subtree;
            $subtree = $subtree2bintree{$subtree} =
              $insert_bintree->($subtree, $order, $depth + 1);
        }
    };

    my $merge_subtrees = sub {
        my ($tree, $order) = @_;

        # Process leaf nodes first.
        for my $href (values %$tree) {
            for my $href (values %$href) {
                $merge_subtrees1->($href, $order, 2);
            }
        }

        # Process nodes next to leaf nodes.
        for my $href (values %$tree) {
            $merge_subtrees1->($href, $order, 1);
        }

        # Process nodes next to root.
        $merge_subtrees1->($tree, $order, 0);
        return $insert_bintree->($tree, $order, 0);
    };

    # Add new chain to current router.
    my $new_chain = sub {
        my ($rules) = @_;
        my $counter = $router_data->{chain_counter}++;
        my $chain   = { name  => "c$counter", rules => $rules, };
        push @{ $router_data->{chains} }, $chain;
        return $chain;
    };

    my $gen_chain;
    $gen_chain = sub {
        my ($tree, $order, $depth) = @_;
        my $key = $order->[$depth];
        my @rules;

        # We need the original value later.
        my $bintree = $tree;
        while (1) {
            my ($hi, $lo, $seq, $subtree) =
              @{$bintree}{qw(hi lo seq subtree)};
            $seq = undef if $seq and not @$seq;
            if (not $seq) {
                push @$seq, $hi if $hi;
                push @$seq, $lo if $lo;
            }
            if ($subtree) {

#               if($order->[$depth+1]&&
#                  $order->[$depth+1] =~ /^(src|dst)$/) {
#                   debug($order->[$depth+1]);
#                   debug_bintree($subtree);
#               }
                my $rules = $cache{$subtree};
                if (not $rules) {
                    $rules =
                      $depth + 1 >= @$order
                      ? [ { action => $subtree } ]
                      : $gen_chain->($subtree, $order, $depth + 1);
                    if (@$rules > 1 and not $bintree->{noop}) {
                        my $chain = $new_chain->($rules);
                        $rules = [ { action => $chain, goto => 1 } ];
                    }
                    $cache{$subtree} = $rules;
                }

                my @add_keys;

                # Don't use "goto", if some tests for sub-nodes of
                # $subtree are following.
                push @add_keys, (goto => 0)        if $seq;
                push @add_keys, ($key => $bintree) if not $bintree->{noop};
                if (@add_keys) {

                    # Create a copy of each rule because we must not change
                    # the original cached rules.
                    push @rules, map {
                        { (%$_, @add_keys) }
                    } @$rules;
                }
                else {
                    push @rules, @$rules;
                }
            }
            last if not $seq;

            # Take this value in next iteration.
            $bintree = pop @$seq;

            # Process remaining elements.
            for my $node (@$seq) {
                my $rules = $gen_chain->($node, $order, $depth);
                push @rules, @$rules;
            }
        }
        if (@rules > 1 and not $tree->{noop}) {

            # Generate new chain. All elements of @seq are
            # known to be disjoint. If one element has matched
            # and branched to a chain, then the other elements
            # need not be tested again. This is implemented by
            # calling the chain using '-g' instead of the usual '-j'.
            my $chain = $new_chain->(\@rules);
            return [ { action => $chain, goto => 1, $key => $tree } ];
        }
        else {
            return \@rules;
        }
    };

    # Build rule trees. Generate and process separate tree for
    # adjacent rules with same action.
    my @rule_trees;
    my %tree2order;
    if (@$rules) {
        my $prev_action = $rules->[0]->{action};

        # Special rule as marker, that end of rules has been reached.
        push @$rules, { action => 0 };
        my $start = my $i = 0;
        my $last = $#$rules;
        my %count;
        while (1) {
            my $rule   = $rules->[$i];
            my $action = $rule->{action};
            if ($action eq $prev_action) {

                # Count, which key has the largest number of
                # different values.
                for my $what (qw(src dst src_range prt)) {
                    $count{$what}{ $rule->{$what} } = 1;
                }
                $i++;
            }
            else {

                # Use key with smaller number of different values
                # first in rule tree. This gives smaller tree and
                # fewer tests in chains.
                my @test_order =
                  sort { keys %{ $count{$a} } <=> keys %{ $count{$b} } }
                  qw(src_range dst prt src);
                my $rule_tree;
                my $end = $i - 1;
                for (my $j = $start ; $j <= $end ; $j++) {
                    my $rule = $rules->[$j];
                    my ($action, $t1, $t2, $t3, $t4) =
                      @{$rule}{ 'action', @test_order };
                    ($t1, $t2, $t3, $t4) = 
                        map { $_->{name} } ($t1, $t2, $t3, $t4);
                    $rule_tree->{$t1}->{$t2}->{$t3}->{$t4} = $action;
                }
                push @rule_trees, $rule_tree;

#   	    debug(join ', ', @test_order);
                $tree2order{$rule_tree} = \@test_order;
                last if not $action;
                $start       = $i;
                $prev_action = $action;
            }
        }
        @$rules = ();
    }

    for (my $i = 0 ; $i < @rule_trees ; $i++) {
        my $tree  = $rule_trees[$i];
        my $order = $tree2order{$tree};

#       $print_tree->($tree, $order, 0);
        $tree = $merge_subtrees->($tree, $order);
        my $result = $gen_chain->($tree, $order, 0);

        # Goto must not be used in last rule of rule tree which is
        # not the last tree.
        if ($i != $#rule_trees) {
            my $rule = $result->[-1];
            delete $rule->{goto};
        }

        # Postprocess rules: Add missing attributes prt, src, dst
        # with no-op values.
        for my $rule (@$result) {
            $rule->{src} ||= $network_00;
            $rule->{dst} ||= $network_00;
            my $prt     = $rule->{prt};
            my $src_range = $rule->{src_range};
            if (not $prt and not $src_range) {
                $rule->{prt} = $prt_ip;
            }
            elsif (not $prt) {
                $rule->{prt} =
                    $src_range->{proto} eq 'tcp'  ? $prt_tcp
                  : $src_range->{proto} eq 'udp'  ? $prt_udp
                  : $src_range->{proto} eq 'icmp' ? $prt_icmp
                  :                                 $prt_ip;
            }
        }
        push @$rules, @$result;
    }
    $acl_info->{rules} = $rules;
    return;
}

# Given an IP and mask, return its address
# as "x.x.x.x/x" or "x.x.x.x" if prefix == 32.
sub prefix_code {
    my ($ip_net) = @_;
    my ($ip, $mask) = @{$ip_net}{qw(ip mask)};
    my $ip_code     = bitstr2ip($ip);
    my $prefix_code = mask2prefix($mask);
    return $prefix_code == 32 ? $ip_code : "$ip_code/$prefix_code";
}

# Print chains of iptables.
# Objects have already been normalized to ip/mask pairs.
# NAT has already been applied.
sub print_chains {
    my ($router_data) = @_;
    my $chains = $router_data->{chains};
    @$chains or return;

    my $acl_info   = $router_data->{acls}->[0];
    my $prt2obj    = $acl_info->{prt2obj};
    my $prt_ip     = $prt2obj->{ip};
    my $prt_icmp   = $prt2obj->{icmp};
    my $prt_tcp    = $prt2obj->{'tcp 1 65535'};
    my $prt_udp    = $prt2obj->{'udp 1 65535'};

    # Declare chain names.
    for my $chain (@$chains) {
        my $name = $chain->{name};
        print ":$name -\n";
    }

    # Define chains.
    for my $chain (@$chains) {
        my $name   = $chain->{name};
        my $prefix = "-A $name";

#	my $steps = my $accept = my $deny = 0;
        for my $rule (@{ $chain->{rules} }) {
            my $action = $rule->{action};
            my $action_code =
                ref($action)        ? $action->{name}
              : $action eq 'permit' ? 'ACCEPT'
              :                       'droplog';

            # Calculate maximal number of matches if
            # - some rules matches (accept) or
            # - all rules don't match (deny).
#	    $steps += 1;
#	    if ($action eq 'permit') {
#		$accept = max($accept, $steps);
#	    }
#	    elsif ($action eq 'deny') {
#		$deny = max($deny, $steps);
#	    }
#	    elsif ($rule->{goto}) {
#		$accept = max($accept, $steps + $action->{a});
#	    }
#	    else {
#		$accept = max($accept, $steps + $action->{a});
#		$steps += $action->{d};
#	    }

            my $jump = $rule->{goto} ? '-g' : '-j';
            my $result = "$jump $action_code";
            if (my $src = $rule->{src}) {
                if ($src->{mask} ne $zero_ip) {
                    $result .= ' -s ' . prefix_code($src);
                }
            }
            if (my $dst = $rule->{dst}) {
                if ($dst->{mask} ne $zero_ip) {
                    $result .= ' -d ' . prefix_code($dst);
                }
            }
          ADD_PROTO:
            {
                my $src_range = $rule->{src_range};
                my $prt       = $rule->{prt};
                last ADD_PROTO if not $src_range and not $prt;
                last ADD_PROTO if $prt and $prt->{proto} eq 'ip';
                if (not $prt) {
                    last ADD_PROTO if $src_range->{proto} eq 'ip';
                    $prt =
                        $src_range->{proto} eq 'tcp'  ? $prt_tcp
                      : $src_range->{proto} eq 'udp'  ? $prt_udp
                      : $src_range->{proto} eq 'icmp' ? $prt_icmp
                      :                                 $prt_ip;
                }

#               debug("c ",print_rule $rule) if not $src_range or not $prt;
                $result .= ' ' . iptables_prt_code($src_range, $prt);
            }
            print "$prefix $result\n";
        }

#	$deny = max($deny, $steps);
#	$chain->{a} = $accept;
#	$chain->{d} = $deny;
#	print "# Max tests: Accept: $accept, Deny: $deny\n";
    }

    # Empty line as delimiter.
    print "\n";
    return;
}

sub iptables_acl_line {
    my ($rule, $prefix) = @_;
    my ($action, $src, $dst, $src_range, $prt) =
      @{$rule}{qw(action src dst src_range prt)};
    my $action_code =
        ref($action)        ? $action->{name}
      : $action eq 'permit' ? 'ACCEPT'
      :                       'droplog';
    my $jump = $rule->{goto} ? '-g' : '-j';
    my $result = "$prefix $jump $action_code";
    if ($src->{mask} ne $zero_ip) {
        $result .= ' -s ' . prefix_code($src);
    }
    if ($dst->{mask} ne $zero_ip) {
        $result .= ' -d ' . prefix_code($dst);
    }
    if ($prt->{proto} ne 'ip') {
        $result .= ' ' . iptables_prt_code($src_range, $prt);
    }
    print "$result\n";
    return;
}

sub print_iptables_acl {
    my ($acl_info) = @_;
    my $name = $acl_info->{name};
    print ":$name -\n";
    my $rules = $acl_info->{rules};
    my $intf_prefix = "-A $name";
    for my $rule (@$rules) {
        iptables_acl_line($rule, $intf_prefix);
    }
}
*/

func convert_rule_objects (rules []*jRule, ip_net2obj Name2IP_Net, prt2obj Name2Proto) Rules {
	if rules == nil { return nil }
	var expanded Rules
	for _, rule := range rules {
		src_list := ip_net_list(rule.Src, ip_net2obj)
		dst_list := ip_net_list(rule.Dst, ip_net2obj)
		prt_list := prt_list(rule.Prt, prt2obj)
		var src_range *Proto
		if rule.Src_range != "" {
			src_range = prt(rule.Src_range, prt2obj)
		}
		for _, src := range src_list {
			for _, dst := range dst_list {
				for _, prt := range prt_list {
					expanded.push(
						&Expanded_Rule{
							deny: rule.Deny == 1,
							src: src,
							dst: dst, 
							src_range : src_range,
							prt: prt,
							opt_secondary: rule.Opt_secondary == 1,
						})
				}
			}
		}
	}
	return expanded
}
	
type Router_Data struct {
	model string
	acls []*ACL_Info
	log_deny string
	filter_only_group *IP_Net
	do_objectgroup bool
	obj_groups_hash map[group_key][]*Obj_Group
	obj_group_counter int
}

func ip_net_list (names []string, ip_net2obj Name2IP_Net) ([]*IP_Net) {
	if names == nil {
		return nil
	}
	result := make([]*IP_Net, len(names))
	for i, name := range names {
		obj, ok := ip_net2obj[name];
		if !ok {
			obj = create_ip_obj(name)
			ip_net2obj[name] = obj
		}
		result[i] = obj
	}
	return result
}

func prt_list (names []string, prt2obj Name2Proto) ([]*Proto) {
	if names == nil {
		return nil
	}
	result := make([]*Proto, len(names))
	for i, name := range names {
		obj, ok := prt2obj[name];
		if !ok {
			obj = create_prt_obj(name)
			prt2obj[name] = obj
		}
		result[i] = obj
	}
	return result
}

func prt (name string, prt2obj Name2Proto) (*Proto) {
	obj, ok := prt2obj[name]
	if !ok {
		obj = create_prt_obj(name)
		prt2obj[name] = obj
	}
	return obj
}

//go:generate easyjson Pass2.go
//easyjson:json
type jRouter_Data struct {
	Model string			`json:"model"`
	Acls []jACL_Info		`json:"acls"`
	Filter_only []string	`json:"filter_only"`
	Do_objectgroup int	`json:"do_objectgroup"`
}
type jACL_Info struct {
	Name string				`json:"name"`
	Is_std_acl int			`json:"is_std_acl"`
	Intf_rules []*jRule	`json:"intf_rules"`
	Rules []*jRule			`json:"rules"`
	Opt_networks []string	`json:"opt_networks"`
	No_opt_addrs []string	`json:"no_opt_addrs"`
	Need_protect []string	`json:"need_protect"`
	Filter_any_src int	`json:"filter_any_src"`
	Is_crypto_acl int		`json:"is_crypto_acl"`
	Add_permit int			`json:"add_permit"`
	Add_deny int			`json:"add_deny"`
}
type jRule struct {
	Deny int				`json:"deny"`
	Src []string		`json:"src"`
	Dst []string		`json:"dst"`
	Prt []string		`json:"prt"`
	Src_range string	`json:"src_range"`
	Opt_secondary int	`json:"opt_secondary"`
}

func prepare_acls (path string) (router_data Router_Data) {
	var jdata jRouter_Data
	data, err := ioutil.ReadFile(path)
	if err != nil { panic(err) }
	err = easyjson.Unmarshal(data, &jdata)
	if err != nil { panic(err) }
	model := jdata.Model
	router_data.model = model
	do_objectgroup := jdata.Do_objectgroup == 1
	router_data.do_objectgroup = do_objectgroup
	raw_acls := jdata.Acls
	acls := make([]*ACL_Info, len(raw_acls))
	for i, raw_info := range raw_acls {
		
		// Process networks and protocols of each interface individually,
		// because relation between networks may be changed by NAT.
		ip_net2obj := make(Name2IP_Net)
		prt2obj    := make(Name2Proto)

		intf_rules := convert_rule_objects(
			raw_info.Intf_rules, ip_net2obj, prt2obj)
		rules := convert_rule_objects(raw_info.Rules, ip_net2obj, prt2obj)

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
		setup_ip_net_relation(ip_net2obj)

		acl_info := ACL_Info{
			name: raw_info.Name,
			is_std_acl: raw_info.Is_std_acl == 1,
			intf_rules: intf_rules,
			rules: rules,
			prt2obj: prt2obj,
			ip_net2obj: ip_net2obj,
			filter_only: filter_only,
			opt_networks: opt_networks,
			no_opt_addrs: no_opt_addrs,
			filter_any_src: raw_info.Filter_any_src == 1,
			need_protect: need_protect,
			network_00: ip_net2obj["0.0.0.0/0"],
		}
		acls[i] = &acl_info
    
		if need_protect != nil {
			mark_supernets_of_need_protect(need_protect)
		}
		if model == "Linux" {
//            add_tcp_udp_icmp(prt2obj);
		}
        
		setup_prt_relation(prt2obj);
		acl_info.prt_ip = prt2obj["ip"]
        
		if model == "Linux" {
//			find_chains(acl_info, router_data);
		} else {
			intf_rules = optimize_rules(intf_rules, acl_info)
			intf_rules = join_ranges(intf_rules, prt2obj)
			rules = optimize_rules(rules, acl_info)
			rules = join_ranges(rules, prt2obj)
			acl_info.intf_rules = move_rules_esp_ah(intf_rules, prt2obj)
			acl_info.rules = move_rules_esp_ah(rules, prt2obj)

			has_final_permit := check_final_permit(&acl_info);
			add_permit       := raw_info.Add_permit == 1
			add_deny         := raw_info.Add_deny   == 1
			add_protect_rules(&acl_info, has_final_permit || add_permit)
			if do_objectgroup && raw_info.Is_crypto_acl != 1 {
				find_objectgroups(&acl_info, &router_data);
			}
			if filter_only != nil && !add_permit {
				add_local_deny_rules(&acl_info, &router_data);
			} else if !has_final_permit {
				add_final_permit_deny_rule(&acl_info, add_deny, add_permit);
			}
		}
	}
	router_data.acls = acls
	return
}

// Given IP or group object, return its address in Cisco syntax.
func cisco_acl_addr (obj *IP_Net, model string) string {

	// Object group.
	if obj.net == nil {
		var keyword string
		if model == "NX-OS" {
			keyword = "addrgroup"
		} else {
			keyword = "object-group"
		}
		return keyword + " " + obj.name
	}

	ip, mask := obj.net.IP, net.IP(obj.net.Mask)
	if mask.Equal(zero_ip) {
		return "any"
	} else if model == "NX-OS" {
		return obj.name
	} else {
		ip_code := ip.String()
		if mask.Equal(max_ip) {
			return "host " + ip_code
		} else {
			
			// Inverse mask bits.
			// Must not inverse original mask, shared by multiple rules.
			if model == "NX-OS" || model == "IOS" {
				copy := make([]byte, len(mask));
				for i, byte := range mask {
					copy[i] = ^byte
				}
				mask = copy;
			}
			mask_code := mask.String()
			return ip_code + " " + mask_code
		}
	}
}

func print_object_groups (groups []*Obj_Group, acl_info *ACL_Info, model string) {
	var keyword string
	if model == "NX-OS" {
		keyword = "object-group ip address"
	} else {
		keyword = "object-group network"
	}
	for _, group := range groups {
		numbered := 10
		fmt.Println(keyword, group.name)
		for _, element := range group.elements {
			adr := cisco_acl_addr(element, model)
			if model == "NX-OS" {
				fmt.Println("", numbered, adr)
				numbered += 10
			} else if (model == "ACE") {
				fmt.Println("", adr)
			} else {
				fmt.Println(" network-object", adr)
			}
		}
	}
}

// Returns 3 values for building a Cisco ACL:
// permit <val1> <src> <val2> <dst> <val3>
func cisco_prt_code (src_range, prt *Proto) (t1, t2, t3 string) {
	proto := prt.proto
	
	if proto == "ip" {
        return "ip", "", ""
	} else if proto == "tcp" || proto == "udp" {
		port_code := func (range_obj *Proto) string {
			ports := range_obj.ports
			v1, v2 := ports[0], ports[1]
			if v1 == v2 {
				return fmt.Sprint("eq ", v1)
			} else if v1 == 1 && v2 == 65535 {
				return ""
			} else if v2 == 65535 {
				return fmt.Sprint("gt ", v1 - 1)
			} else if v1 == 1 {
				return fmt.Sprint("lt ", v2 + 1)
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
		if nil != src_range {
			src_prt = port_code(src_range)
		}
		return proto, src_prt, dst_prt
	} else if proto == "icmp" {
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
	} else {
		return proto, "", ""
	}
}

func get_cisco_action (deny bool) string {
	var action string
	if deny {
		action = "deny"
	} else {
		action = "permit"
	}
	return action
}

func print_asa_std_acl (acl_info *ACL_Info, model string) {
	rules := acl_info.rules
	for _, rule := range rules {
		fmt.Println(
			"access-list",
			acl_info.name,
			"standard",
			get_cisco_action(rule.deny),
			cisco_acl_addr(rule.src, model))
	}
}

func print_cisco_acl (acl_info *ACL_Info, router_data Router_Data) {
	model := router_data.model

	if acl_info.is_std_acl {
		print_asa_std_acl(acl_info, model)
		return
	}

	intf_rules := acl_info.intf_rules
	rules := acl_info.rules
	name := acl_info.name
	numbered := int(10)
	var prefix string
	if model == "IOS" {
		fmt.Println("ip access-list extended", name)
	} else if model == "NX-OS" {
		fmt.Println("ip access-list", name)
	} else if model == "ASA" || model == "ACE" {
		prefix = "access-list " + name + " extended"
	}

	for _, rules := range []Rules{intf_rules, rules} {
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
			fmt.Println(result)
		}
	}
}

func print_acl (acl_info *ACL_Info, router_data Router_Data) {
	model := router_data.model

	if model == "Linux" {

		// Print all sub-chains at once before first toplevel chain is printed.
		/*
		if router_data.chains != nil {
			print_chains(router_data)
			router_data.chains = nil
		}
		print_iptables_acl(acl_info)
      */
	} else {
		if groups := acl_info.object_groups; groups != nil {
			print_object_groups(groups, acl_info, model)
		}
		print_cisco_acl(acl_info, router_data)
	}
}

func print_combined (config []string, router_data Router_Data, out_path string) {

	// Redirect print statements to out_path.
	out_fd, err := os.Create(out_path)
	if err != nil {
		fatal_err("Can't open %s for writing: %v", out_path, err)
	}
	old := os.Stdout
	defer func () { os.Stdout = old }()
	os.Stdout = out_fd;

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
			name := line[indexes[2] : indexes[3]]
			acl_info, found := acl_hash[name]
			if !found { fatal_err("Unexpected ACL %s", name) }
			print_acl(acl_info, router_data);
		} else {
			// Print unchanged config line.
			fmt.Println(line)
		}
    }   

	if err := out_fd.Close(); err != nil {
		fatal_err("Can't close %s: %v", out_path, err)
	}
}

func isDir (path string) bool {
	stat, err := os.Stat(path) 
	return err == nil && stat.Mode().IsDir()
}

func isRegular (path string) bool {
	stat, err := os.Stat(path) 
	return err == nil && stat.Mode().IsRegular()
}

// Try to use pass2 file from previous run.
// If identical files with extension .config and .rules
// exist in directory .prev/, then use copy.
func try_prev (device_name, dir, prev string) bool {
	if !isDir(prev) {
		return false
	}
	prev_file := prev + "/" + device_name
	if !isRegular(prev_file) {
		return false
	}
	code_file := dir + "/" + device_name
	for _, ext := range [...]string{"config", "rules"} {
		pass1name := code_file + "." + ext
		pass1prev := prev_file + "." + ext
      if !isRegular(pass1prev) { return false }
		cmd := exec.Command("cmp", "-s", pass1name, pass1prev)
		if cmd.Run() != nil { return false }
	}
	cmd := exec.Command("cp", "-p", prev_file, code_file)
	if cmd.Run() != nil { return false }

	// File was found and copied successfully.
	diag_msg("Reused .prev/" + device_name)
	return true
}

func read_file_lines (filename string) []string {
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

func pass2_file (device_name, dir string, c chan bool) {
//	success := false

	// Send ok on success
//	defer func () { c <- success }()

	file := dir + "/" + device_name
	router_data := prepare_acls(file + ".rules")
	config := read_file_lines(file + ".config")
	print_combined(config, router_data, file)
//	success = true
}

func apply_concurrent (device_names_fh *os.File, dir, prev string) {

	var generated, reused, errors int;
	concurrent := config.concurrent
	c := make(chan bool, concurrent)
	workers_left := concurrent

	wait_and_check := func () {
		if <-c {
			generated++;
		} else {
			errors++
		}
	}
		
	// Read to be processed files line by line.
	scanner := bufio.NewScanner(device_names_fh)
	for scanner.Scan() {
		device_name := scanner.Text()

		if try_prev(device_name, dir, prev) {
			reused++
		} else if 0 < workers_left {
			// Start concurrent jobs at beginning.
			/*
			go pass2_file(device_name, dir, c)
			workers_left--
         */
			pass2_file(device_name, dir, c)
		} else {
			// Start next job, after some job has finished.
			wait_and_check()
			go pass2_file(device_name, dir, c)
		}
	}
	
	// Wait for all jobs to be finished.
	/*
	for 0 < len(c) {
		wait_and_check()
	}
   */

	if err := scanner.Err(); err != nil {
		fatal_err("While reading device names: %v", err)
	}

	if errors > 0 {
		fatal_err("Failed")
	}
	if generated > 0 {
		info("Generated files for %d devices", generated);
	}
	if reused > 0 {
		info("Reused %d files from previous run", reused);
	}
}


func pass2 (dir string) {
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
	
	apply_concurrent(from_pass1, dir, prev);
	
	// Remove directory '.prev' created by pass1
	// or remove symlink '.prev' created by newpolicy.pl.
	err := os.RemoveAll(prev)
	if err != nil {
		fatal_err("Can't remove %s: %v", prev, err)
	}
}

func main() {
	if (len(os.Args) != 2) {
		fatal_err("Usage: %s DIR", os.Args[0]);
	}
	var dir = os.Args[1]
	pass2(dir)
}
