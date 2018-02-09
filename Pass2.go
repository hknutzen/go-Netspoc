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

// Config holds program flags.
type Config struct {
	concurrent int
	pipe       bool
	verbose    bool
}

var (
	showDiag = false
	config   = Config{
		concurrent: 8,
		pipe:       false,
		verbose:    false,
	}
)

func toStderr(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format, args...)
	fmt.Fprintln(os.Stderr)
}

func fatalErr(format string, args ...interface{}) {
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

func diagMsg(msg string) {
	if os.Getenv("SHOW_DIAG") != "" {
		fmt.Fprintln(os.Stderr, "DIAG: "+msg)
	}
}

type ipNet struct {
	*net.IPNet
	optNetworks             *ipNet
	noOptAddrs, needProtect bool
	name                    string
	up                      *ipNet
	isSupernetOfNeedProtect map[*ipNet]bool
}
type Proto struct {
	proto       string
	ports       [2]int
	established bool
	icmpType    int
	icmpCode    int
	name        string
	up          *Proto
	hasNeighbor bool
}
type name2ipNet map[string]*ipNet
type name2Proto map[string]*Proto

func createIPObj(ipNetName string) *ipNet {
	_, net, _ := net.ParseCIDR(ipNetName)
	return &ipNet{IPNet: net, name: ipNetName}
}

func getIPObj(ip net.IP, mask net.IPMask, ipNet2obj name2ipNet) *ipNet {
	prefix, _ := mask.Size()
	name := fmt.Sprintf("%s/%d", ip.String(), prefix)
	obj, ok := ipNet2obj[name]
	if !ok {
		obj = &ipNet{IPNet: &net.IPNet{IP: ip, Mask: mask}, name: name}
		ipNet2obj[name] = obj
	}
	return obj
}

func createPrtObj(descr string) *Proto {
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
			prt.icmpType, _ = strconv.Atoi(splice[1])
			if len(splice) > 2 {
				prt.icmpCode, _ = strconv.Atoi(splice[2])
			} else {
				prt.icmpCode = -1
			}
		} else {
			prt.icmpType = -1
		}
	}
	return &prt
}

func getNet00Addr(ipv6 bool) string {
	var result string
	if ipv6 {
		result = "::/0"
	} else {
		result = "0.0.0.0/0"
	}
	return result
}

func setupIPNetRelation(ipNet2obj name2ipNet, ipv6 bool) {
	net00 := getNet00Addr(ipv6)
	if _, ok := ipNet2obj[net00]; !ok {
		ipNet2obj[net00] = createIPObj(net00)
	}
	maskIPHash := make(map[string]map[string]*ipNet)

	// Collect networks into maskIPHash.
	for _, network := range ipNet2obj {
		ip, mask := network.IP, network.Mask
		ipMap, ok := maskIPHash[string(mask)]
		if !ok {
			ipMap = make(map[string]*ipNet)
			maskIPHash[string(mask)] = ipMap
		}
		ipMap[string(ip)] = network
	}

	// Compare networks.
	// Go from smaller to larger networks.
	var maskList []net.IPMask
	for k := range maskIPHash {
		maskList = append(maskList, net.IPMask(k))
	}
	less := func(i, j int) bool {
		return bytes.Compare(maskList[i], maskList[j]) == -1
	}
	sort.Slice(maskList, func(i, j int) bool { return less(j, i) })
	for i, mask := range maskList {
		upperMasks := maskList[i+1:]

		// No supernets available
		if len(upperMasks) == 0 {
			break
		}

		ipHash := maskIPHash[string(mask)]
		for ip, subnet := range ipHash {

			// Find networks which include current subnet.
			// upperMasks holds masks of potential supernets.
			for _, m := range upperMasks {

				i := net.IP(ip).Mask(net.IPMask(m))
				bignet, ok := maskIPHash[string(m)][string(i)]
				if ok {
					subnet.up = bignet
					break
				}
			}
		}
	}

	// Propagate content of attribute optNetworks to all subnets.
	// Go from large to smaller networks.
	sort.Slice(maskList, less)
	for _, mask := range maskList {
		for _, network := range maskIPHash[string(mask)] {
			up := network.up
			if up == nil {
				continue
			}
			if optNetworks := up.optNetworks; optNetworks != nil {
				network.optNetworks = optNetworks
			}
		}
	}
}

func markSupernetsOfNeedProtect(needProtect []*ipNet) {
	for _, intf := range needProtect {
		up := intf.up
		for up != nil {
			if up.isSupernetOfNeedProtect == nil {
				up.isSupernetOfNeedProtect = make(map[*ipNet]bool)
			}
			up.isSupernetOfNeedProtect[intf] = true
			up = up.up
		}
	}
}

// Needed for model=Linux.
func addTCPUDPIcmp(prt2obj name2Proto) {
	_ = prt("tcp 1 65535", prt2obj)
	_ = prt("udp 1 65535", prt2obj)
	_ = prt("icmp", prt2obj)
}

// Set {up} relation from port range to the smallest port range which
// includes it.
// If no including range is found, link it with next larger protocol.
// Set attribute {hasNeighbor} to range adjacent to upper port.
// Abort on overlapping ranges.
func orderRanges(proto string, prt2obj name2Proto, up *Proto) {
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
	// Set attributes {up} and {hasNeighbor}.
	// Return position of range which isn't sub-range or undef
	// if end of array is reached.
	var checkSubrange func(a *Proto, a1, a2, i int) int
	checkSubrange = func(a *Proto, a1, a2, i int) int {
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
				a.hasNeighbor = true
				b.hasNeighbor = true

				// Mark other ranges having identical start port.
				for _, c := range ranges[i+1:] {
					if c.ports[0] != b1 {
						break
					}
					c.hasNeighbor = true
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
				i = checkSubrange(b, b1, b2, i+1)

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
			fatalErr(
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
		index = checkSubrange(a, a1, a2, index+1)
		if index == 0 {
			return
		}
	}
}

func setupPrtRelation(prt2obj name2Proto) {
	prtIP := prt("ip", prt2obj)
	icmpUp, ok := prt2obj["icmp"]
	if !ok {
		icmpUp = prtIP
	}

	for _, prt := range prt2obj {
		proto := prt.proto
		if proto == "icmp" {
			if prt.icmpType != -1 {
				if prt.icmpCode != -1 {
					up, ok := prt2obj[fmt.Sprint("icmp ", prt.icmpType)]
					if !ok {
						up = icmpUp
					}
					prt.up = up
				} else {
					prt.up = icmpUp
				}
			} else {
				prt.up = prtIP
			}
		} else if _, err := strconv.Atoi(proto); err == nil {

			// Numeric protocol.
			prt.up = prtIP
		}
	}

	orderRanges("tcp", prt2obj, prtIP)
	orderRanges("udp", prt2obj, prtIP)

	if tcpEstabl, ok := prt2obj["tcp 1 65535 established"]; ok {
		up, ok := prt2obj["tcp 1 65535"]
		if !ok {
			up = prtIP
		}
		tcpEstabl.up = up
	}
}

/*
#sub printRule {
#    my ($rule) = @_;
#    my ($deny, $src, $dst, $prt) = @{$rule}{qw(deny src dst prt)};
#    my $action = $deny ? 'deny' : 'permit';
#    return "$action $src->{name} $dst->{name} $prt->{name}";
#}
*/

func optimizeRedundantRules(cmpHash, chgHash RuleTree) bool {
	changed := false
	for deny, chgHash := range chgHash {
		for {
			if cmpHash, found := cmpHash[deny]; found {
				for srcRange, chgHash := range chgHash {
					for {
						if cmpHash, found := cmpHash[srcRange]; found {
							for src, chgHash := range chgHash {
								for {
									if cmpHash, found := cmpHash[src]; found {
										for dst, chgHash := range chgHash {
											for {
												if cmpHash, found := cmpHash[dst]; found {
													for prt, chgRule := range chgHash {
														if chgRule.deleted {
															continue
														}
														for {
															if cmpRule, found := cmpHash[prt]; found {
																if cmpRule != chgRule &&
																	cmpRule.log == chgRule.log {
																	chgRule.deleted = true
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
						srcRange = srcRange.up
						if srcRange == nil {
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
	deny          bool
	src, dst      *ipNet
	prt, srcRange *Proto
	log           string
	deleted       bool
	optSecondary  bool
}

type Rules []*Rule

func (rules *Rules) push(rule *Rule) {
	*rules = append(*rules, rule)
}

// Build rule tree from nested maps.
// Leaf nodes have rules as values.
type RuleTree1 map[*Proto]*Rule
type RuleTree2 map[*ipNet]RuleTree1
type RuleTree3 map[*ipNet]RuleTree2
type RuleTree4 map[*Proto]RuleTree3
type RuleTree map[bool]RuleTree4

func (tree RuleTree2) add(dst *ipNet) RuleTree1 {
	subtree, found := tree[dst]
	if !found {
		subtree = make(RuleTree1)
		tree[dst] = subtree
	}
	return subtree
}
func (tree RuleTree3) add(src *ipNet) RuleTree2 {
	subtree, found := tree[src]
	if !found {
		subtree = make(RuleTree2)
		tree[src] = subtree
	}
	return subtree
}
func (tree RuleTree4) add(srcRange *Proto) RuleTree3 {
	subtree, found := tree[srcRange]
	if !found {
		subtree = make(RuleTree3)
		tree[srcRange] = subtree
	}
	return subtree
}
func (tree RuleTree) add(deny bool) RuleTree4 {
	subtree, found := tree[deny]
	if !found {
		subtree = make(RuleTree4)
		tree[deny] = subtree
	}
	return subtree
}

/*
// Dynamically typed function adds next nesting levels.
// Map for subtrees is created if necessary.
func dynTree(tree interface{}, keys ...interface{}) interface{} {
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

func optimizeRules(rules Rules, aclInfo *ACLInfo) Rules {
	prtIP := aclInfo.prt2obj["ip"]
	changed := false

	// Add rule to rule tree.
	addRule := func(ruleTree RuleTree, rule *Rule) {
		srcRange := rule.srcRange
		if srcRange == nil {
			srcRange = prtIP
		}

		subtree1 :=
			ruleTree.add(rule.deny).add(srcRange).add(rule.src).add(rule.dst)
		//// Build nested ruleTree by dynamically typed operations.
		//// Go back to static type 'RuleTree1'.
		//	dynTree(ruleTree, rule.deny, srcRange, rule.src, rule.dst).(RuleTree1)
		if _, found := subtree1[rule.prt]; found {
			rule.deleted = true
			changed = true
		} else {
			subtree1[rule.prt] = rule
		}
	}

	// For comparing redundant rules.
	ruleTree := make(RuleTree)

	// Fill rule tree.
	for _, rule := range rules {
		addRule(ruleTree, rule)
	}

	changed = optimizeRedundantRules(ruleTree, ruleTree) || changed

	// Implement rules as secondary rule, if possible.
	secondaryTree := make(RuleTree)
	for _, rule := range rules {
		if !rule.optSecondary {
			continue
		}
		if rule.deleted {
			continue
		}
		if rule.src.noOptAddrs {
			continue
		}
		if rule.dst.noOptAddrs {
			continue
		}

		// Replace obj by supernet.
		if rule.src.optNetworks != nil {
			rule.src = rule.src.optNetworks
		}
		if rule.dst.optNetworks != nil && !rule.dst.needProtect {
			rule.dst = rule.dst.optNetworks
		}

		// Change protocol to IP.
		rule.prt = prtIP

		addRule(secondaryTree, rule)
	}

	if len(secondaryTree) != 0 {
		changed =
			optimizeRedundantRules(secondaryTree, secondaryTree) || changed
		changed =
			optimizeRedundantRules(secondaryTree, ruleTree) || changed
	}

	if changed {
		newRules := make(Rules, 0)
		for _, rule := range rules {
			if rule.deleted {
				continue
			}
			newRules.push(rule)
		}
		rules = newRules
	}
	return rules
}

// Join adjacent port ranges.
func joinRanges(rules Rules, prt2obj name2Proto) Rules {
	type key struct {
		deny       bool
		src, dst   *ipNet
		srcRange   *Proto
		log, proto string
	}
	changed := false
	key2rules := make(map[key]Rules)
	for _, rule := range rules {

		// Only ranges which have a neighbor may be successfully optimized.
		// Currently only dstRanges are handled.
		if !rule.prt.hasNeighbor {
			continue
		}

		// Collect rules with identical deny/src/dst/srcRange log values
		// and identical TCP or UDP protocol.
		k := key{
			rule.deny, rule.src, rule.dst, rule.srcRange, rule.log,
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
		// 'orderRanges'. There can't be sub-ranges, because they have
		// been deleted as redundant already.
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i].prt.ports[0] < sorted[j].prt.ports[0]
		})
		ruleA := sorted[0]
		a1, a2 := ruleA.prt.ports[0], ruleA.prt.ports[1]
		for _, ruleB := range sorted[1:] {
			b1, b2 := ruleB.prt.ports[0], ruleB.prt.ports[1]

			// Found adjacent port ranges.
			if a2+1 == b1 {

				// Extend range of previous two or more elements.
				if ports, ok := rule2range[ruleA]; ok {

					ports[1] = b2
					rule2range[ruleB] = ports
					delete(rule2range, ruleA)
				} else {

					// Combine ranges of $ruleA and $ruleB.
					rule2range[ruleB] = [...]int{a1, b2}
				}

				// Mark previous rule as deleted.
				ruleA.deleted = true
				changed = true
			}
			ruleA = ruleB
			a1, a2 = b1, b2
		}
	}

	if changed {
		var newRules Rules
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
				// This is needed for findObjectgroups to work.
				newPrt, ok := prt2obj[key]
				if !ok {
					newPrt = &Proto{proto: proto, ports: ports}
					prt2obj[key] = newPrt
				}
				rule.prt = newPrt
			}
			newRules.push(rule)
		}
		rules = newRules
	}
	return rules
}

type ACLInfo struct {
	name                                             string
	isStdACL                                         bool
	intfRules, rules                                 Rules
	lrules                                           LinuxRules
	prt2obj                                          name2Proto
	ipNet2obj                                        name2ipNet
	filterOnly, optNetworks, noOptAddrs, needProtect []*ipNet
	filterAnySrc                                     bool
	network00                                        *ipNet
	prtIP                                            *Proto
	objectGroups                                     []*ObjGroup
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
func moveRulesEspAh(rules Rules, prt2obj name2Proto, hasLog bool) Rules {
	prtEsp := prt2obj["50"]
	prtAh := prt2obj["51"]
	if prtEsp == nil && prtAh == nil && !hasLog {
		return rules
	}
	if rules == nil {
		return nil
	}
	var denyRules, cryptoRules, permitRules Rules
	for _, rule := range rules {
		if rule.deny {
			denyRules.push(rule)
		} else if rule.prt == prtEsp || rule.prt == prtAh || rule.log != "" {
			cryptoRules.push(rule)
		} else {
			permitRules.push(rule)
		}
	}

	// Sort crypto rules.
	cmpAddr := func(a, b *ipNet) int {
		if val := bytes.Compare(a.IP, b.IP); val != 0 {
			return val
		}
		return bytes.Compare(a.Mask, b.Mask)
	}
	sort.Slice(cryptoRules, func(i, j int) bool {
		switch strings.Compare(
			cryptoRules[i].prt.proto,
			cryptoRules[j].prt.proto) {
		case -1:
			return true
		case 1:
			return false
		}
		switch cmpAddr(cryptoRules[i].src, cryptoRules[j].src) {
		case -1:
			return true
		case 1:
			return false
		}
		return cmpAddr(cryptoRules[i].dst, cryptoRules[j].dst) == -1
	})
	return append(denyRules, append(cryptoRules, permitRules...)...)
}

func createGroup(elements []*ipNet, aclInfo *ACLInfo, routerData *RouterData) *ObjGroup {
	name := fmt.Sprintf("g%d", routerData.objGroupCounter)
	groupRef := &ipNet{IPNet: nil, name: name}
	group := &ObjGroup{
		name:     name,
		elements: elements,
		ref:      groupRef,
	}
	routerData.objGroupCounter++

	// Store group for later printing of its definition.
	aclInfo.objectGroups = append(aclInfo.objectGroups, group)
	return group
}

// Add deny and permit rules at device which filters only locally.
func addLocalDenyRules(aclInfo *ACLInfo, routerData *RouterData) {
	network00, prtIP := aclInfo.network00, aclInfo.prtIP
	filterOnly := aclInfo.filterOnly
	var srcNetworks []*ipNet
	if aclInfo.filterAnySrc {
		srcNetworks = []*ipNet{network00}
	} else {
		srcNetworks = filterOnly
	}

	if routerData.doObjectgroup {
		groupOrSingle := func(objList []*ipNet) *ipNet {
			if len(objList) == 1 {
				return objList[0]
			} else if routerData.filterOnlyGroup != nil {

				// Reuse object-group at all interfaces.
				return routerData.filterOnlyGroup
			} else {
				group := createGroup(objList, aclInfo, routerData)
				routerData.filterOnlyGroup = group.ref
				return group.ref
			}
		}
		aclInfo.rules.push(
			&Rule{
				deny: true,
				src:  groupOrSingle(srcNetworks),
				dst:  groupOrSingle(filterOnly),
				prt:  prtIP,
			})
	} else {
		for _, src := range srcNetworks {
			for _, dst := range filterOnly {
				aclInfo.rules.push(
					&Rule{deny: true, src: src, dst: dst, prt: prtIP})
			}
		}
	}
	aclInfo.rules.push(
		&Rule{src: network00, dst: network00, prt: prtIP})
}

/*
 Purpose    : Create a list of IP/mask objects from a hash of IP/mask names.
              Adjacent IP/mask objects are combined to larger objects.
              It is assumed, that no duplicate or redundant IP/mask objects
              are given.
 Parameters : $hash - hash with IP/mask objects as keys and
                      rules as values.
              $ipNet2obj - hash of all known IP/mask objects
 Result     : Returns reference to array of sorted and combined
              IP/mask objects.
              Parameter $hash is changed to reflect combined IP/mask objects.
*/
func combineAdjacentIPMask(hash map[*ipNet]*Rule, ipNet2obj name2ipNet) []*ipNet {

	// Take objects from keys of map.
	// Sort by IP address. Adjacent networks will be adjacent elements then.
	// Precondition is, that list already has been optimized and
	// therefore has no redundant elements.
	elements := make([]*ipNet, 0, len(hash))
	for element := range hash {
		elements = append(elements, element)
	}
	sort.Slice(elements, func(i, j int) bool {
		return bytes.Compare(elements[i].IP, elements[j].IP) == -1
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
		upMask := net.CIDRMask(prefix, bits)
		ip1 := element1.IP
		ip2 := element2.IP
		if bytes.Compare(ip1.Mask(upMask), ip2.Mask(upMask)) != 0 {
			continue
		}
		upElement := getIPObj(ip1, upMask, ipNet2obj)

		// Substitute left part by combined network.
		elements[i] = upElement

		// Remove right part.
		elements = append(elements[:i+1], elements[i+2:]...)

		// Add new element and remove left and rigth parts.
		hash[upElement] = hash[element1]
		delete(hash, element1)
		delete(hash, element2)

		if i > 0 {
			up2Mask := net.CIDRMask(prefix-1, bits)

			// Check previous network again, if newly created network
			// is right part, i.e. lowest bit of network part is set.
			if !ip1.Equal(ip1.Mask(up2Mask)) {
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

const minObjectGroupSize = 2

type ObjGroup struct {
	name     string
	elements []*ipNet
	ref      *ipNet
	hash     map[string]bool
}

// For searching efficiently for matching group.
type groupKey struct {
	size  int
	first string
}

func findObjectgroups(aclInfo *ACLInfo, routerData *RouterData) {
	ipNet2obj := aclInfo.ipNet2obj

	// Reuse identical groups from different ACLs.
	if routerData.objGroupsHash == nil {
		routerData.objGroupsHash = make(map[groupKey][]*ObjGroup)
	}
	key2group := routerData.objGroupsHash

	// Leave 'intfRules' untouched, because
	// - these rules are ignored at ASA,
	// - NX-OS needs them individually when optimizing needProtect.
	rules := aclInfo.rules

	// Find object-groups in src / dst of rules.
	for _, thisIsDst := range []bool{false, true} {
		type key struct {
			deny          bool
			that          *ipNet
			srcRange, prt *Proto
			log           string
		}
		groupRuleTree := make(map[key]map[*ipNet]*Rule)

		// Find groups of rules with identical
		// deny, srcRange, prt, log, src/dst and different dst/src.
		for _, rule := range rules {
			deny := rule.deny
			srcRange := rule.srcRange
			prt := rule.prt
			log := rule.log
			this := rule.src
			that := rule.dst
			if thisIsDst {
				this, that = that, this
			}
			k := key{deny, that, srcRange, prt, log}
			href, ok := groupRuleTree[k]
			if !ok {
				href = make(map[*ipNet]*Rule)
				groupRuleTree[k] = href
			}
			href[this] = rule
		}

		// Find groups >= minObjectGroupSize,
		// mark rules belonging to one group.
		type glueType struct {

			// Indicator, that group has already been added to some rule.
			active bool

			// object-key => rule, ...
			hash map[*ipNet]*Rule
		}
		groupGlue := make(map[*Rule]*glueType)
		for _, href := range groupRuleTree {

			// href is {dst/src => rule, ...}
			if len(href) < minObjectGroupSize {
				continue
			}

			glue := glueType{hash: href}

			// All this rules have identical deny, srcRange, prt
			// and dst/src and shall be replaced by a single new
			// rule referencing an object group.
			for _, rule := range href {
				groupGlue[rule] = &glue
			}
		}

		// Find group with identical elements
		// or define a new one
		// or return combined network.
		// Returns ipNet object with empty IP, representing a group.
		getGroup := func(hash map[*ipNet]*Rule) *ipNet {

			// Get sorted and combined list of objects from hash of objects.
			// Hash is adjusted, if objects are combined.
			elements := combineAdjacentIPMask(hash, ipNet2obj)
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
			key := groupKey{size, first.name}

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
			group := createGroup(elements, aclInfo, routerData)
			namesInGroup := make(map[string]bool, len(hash))
			for element := range hash {
				namesInGroup[element.name] = true
			}
			group.hash = namesInGroup
			key2group[key] = append(key2group[key], group)
			return group.ref
		}

		// Build new list of rules using object groups.
		newRules := make(Rules, 0)
		for _, rule := range rules {
			if glue, ok := groupGlue[rule]; ok {
				if glue.active {
					continue
				}
				glue.active = true
				groupOrObj := getGroup(glue.hash)
				if thisIsDst {
					rule.dst = groupOrObj
				} else {
					rule.src = groupOrObj
				}
			}
			newRules = append(newRules, rule)
		}
		rules = newRules
	}
	aclInfo.rules = rules
}

func addProtectRules(aclInfo *ACLInfo, hasFinalPermit bool) {
	needProtect := aclInfo.needProtect
	if len(needProtect) == 0 {
		return
	}
	network00, prtIP := aclInfo.network00, aclInfo.prtIP

	// Add deny rules to protect own interfaces.
	// If a rule permits traffic to a directly connected network behind
	// the device, this would accidently permit traffic to an interface
	// of this device as well.

	// To be added deny rule is needless if there is a rule which
	// permits any traffic to the interface.
	// This permit rule can be deleted if there is a permit any any rule.
	noProtect := make(map[*ipNet]bool)
	var deleted int
	rules := aclInfo.intfRules
	for i, rule := range rules {
		if rule.deny {
			continue
		}
		if rule.src != network00 {
			continue
		}
		if rule.prt != prtIP {
			continue
		}
		dst := rule.dst
		if dst.needProtect {
			noProtect[dst] = true
		}

		if hasFinalPermit {
			rules[i] = nil
			deleted++
		}
	}
	if deleted != 0 {
		newRules := make(Rules, 0, len(rules)-deleted)
		for _, rule := range rules {
			if rule != nil {
				newRules.push(rule)
			}
		}
		aclInfo.intfRules = newRules
	}

	// Deny rule is needless if there is no such permit rule.
	// Try to optimize this case.
	protectMap := make(map[*ipNet]bool)
	for _, rule := range aclInfo.rules {
		if rule.deny {
			continue
		}
		if rule.prt.established {
			continue
		}
		hash := rule.dst.isSupernetOfNeedProtect
		if hash == nil {
			continue
		}
		for _, intf := range needProtect {
			if hash[intf] {
				protectMap[intf] = true
			}
		}
	}

	// Protect own interfaces.
	for _, intf := range needProtect {
		if noProtect[intf] || !protectMap[intf] && !hasFinalPermit {
			continue
		}
		aclInfo.intfRules.push(
			&Rule{
				deny: true,
				src:  network00,
				dst:  intf,
				prt:  prtIP,
			})
	}
}

// Check if last rule is 'permit ip any any'.
func checkFinalPermit(aclInfo *ACLInfo) bool {
	rules := aclInfo.rules
	l := len(rules)
	if l == 0 {
		return false
	}
	last := rules[l-1]
	return !last.deny &&
		last.src == aclInfo.network00 &&
		last.dst == aclInfo.network00 &&
		last.prt == aclInfo.prtIP
}

// Add 'deny|permit ip any any' at end of ACL.
func addFinalPermitDenyRule(aclInfo *ACLInfo, addDeny, addPermit bool) {
	if addDeny || addPermit {
		aclInfo.rules.push(
			&Rule{
				deny: addDeny,
				src:  aclInfo.network00,
				dst:  aclInfo.network00,
				prt:  aclInfo.prtIP,
			})
	}
}

// Returns iptables code for filtering a protocol.
func iptablesPrtCode(srcRangeNode, prtNode *PrtBintree) string {
	prt := &prtNode.Proto
	proto := prt.proto
	result := "-p " + proto
	switch proto {
	case "tcp", "udp":
		portCode := func(rangeObj *Proto) string {
			ports := rangeObj.ports
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
		if srcRangeNode != nil {
			if sport := portCode(&srcRangeNode.Proto); sport != "" {
				result += " --sport " + sport
			}
		}
		if dport := portCode(prt); dport != "" {
			result += " --dport " + dport
		}
		return result
	case "icmp":
		icmpType := prt.icmpType
		if icmpType != -1 {
			code := prt.icmpCode
			if code != -1 {
				return fmt.Sprintf("%s --icmp-type %d/%d", result, icmpType, code)
			} else {
				return fmt.Sprintf("%s --icmp-type %d", result, icmpType)
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
func debugBintree (tree *NetBintree, depth string) {
	ip      := tree.IP.String()
	len, _  := tree.Mask.Size()
   var subtree string
	if tree.subtree != nil {
		subtree = "subtree";
	}
	info("%s %s/%d %s", depth, ip, len, subtree)
	if lo := tree.lo; lo != nil {
		debugBintree(lo, depth + "l")
	}
	if hi := tree.hi; hi != nil {
		debugBintree(hi, depth + "r")
	}
}
*/

// Value is LruleTree.
type LruleTree map[NetOrProt]*LruleTree

type NetBintree struct {
	ipNet
	subtree NPBintree
	hi      *NetBintree
	lo      *NetBintree
	noop    bool
}

// Nodes are reverse sorted before being added to bintree.
// Redundant nodes are discarded while inserting.
// A node with value of sub-tree S is discarded,
// if some parent node already has sub-tree S.
func addBintree(tree *NetBintree, node *NetBintree) *NetBintree {
	treeIP, treeMask := tree.IP, tree.Mask
	nodeIP, nodeMask := node.IP, node.Mask
	prefix, bits := treeMask.Size()
	nodePref, _ := nodeMask.Size()
	var result *NetBintree

	// The case where new node is larger than root node will never
	// occur, because nodes are sorted before being added.

	if prefix < nodePref && tree.Contains(nodeIP) {

		// Optimization for this special case:
		// Root of tree has attribute {subtree} which is identical to
		// attribute {subtree} of current node.
		// Node is known to be less than root node.
		// Hence node together with its subtree can be discarded
		// because it is redundant compared to root node.
		// ToDo:
		// If this optimization had been done before mergeSubtrees,
		// it could have merged more subtrees.
		if tree.subtree == nil || node.subtree == nil ||
			tree.subtree != node.subtree {
			mask := net.CIDRMask(prefix+1, bits)
			var hilo **NetBintree
			if nodeIP.Mask(mask).Equal(treeIP) {
				hilo = &tree.lo
			} else {
				hilo = &tree.hi
			}
			if *hilo != nil {
				*hilo = addBintree(*hilo, node)
			} else {
				*hilo = node
			}
		}
		result = tree
	} else {

		// Create common root for tree and node.
		for {
			prefix--
			treeMask = net.CIDRMask(prefix, bits)
			if nodeIP.Mask(treeMask).Equal(treeIP.Mask(treeMask)) {
				break
			}
		}
		result = &NetBintree{
			ipNet: ipNet{
				IPNet: &net.IPNet{IP: nodeIP.Mask(treeMask), Mask: treeMask}},
		}
		if bytes.Compare(nodeIP, treeIP) < 0 {
			result.lo, result.hi = node, tree
		} else {
			result.hi, result.lo = node, tree
		}
	}

	// Merge adjacent sub-networks.
	if result.subtree == nil {
		lo, hi := result.lo, result.hi
		if lo == nil || hi == nil {
			goto NOMERGE
		}
		prefix, _ := result.Mask.Size()
		prefix++
		if loPrefix, _ := lo.Mask.Size(); prefix != loPrefix {
			goto NOMERGE
		}
		if hiPrefix, _ := hi.Mask.Size(); prefix != hiPrefix {
			goto NOMERGE
		}
		if lo.subtree == nil || hi.subtree == nil {
			goto NOMERGE
		}
		if lo.subtree != hi.subtree {
			goto NOMERGE
		}
		if lo.lo != nil || lo.hi != nil || hi.lo != nil || hi.hi != nil {
			goto NOMERGE
		}
		result.subtree = lo.subtree
		result.lo = nil
		result.hi = nil
	}
NOMERGE:
	return result
}

type NetOrProt interface {
}

// Build a binary tree for src/dst objects.
func genAddrBintree(
	elements []*ipNet,
	tree LruleTree,
	tree2bintree map[*LruleTree]NPBintree) *NetBintree {

	// The tree's node is a simplified network object with
	// missing attribute 'name' and extra 'subtree'.
	nodes := make([]*NetBintree, len(elements))
	for i, elem := range elements {
		nodes[i] = &NetBintree{
			ipNet:   *elem,
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

	var bintree *NetBintree
	bintree, nodes = nodes[0], nodes[1:]
	for len(nodes) > 0 {
		var node *NetBintree
		node, nodes = nodes[0], nodes[1:]
		bintree = addBintree(bintree, node)
	}

	// Add attribute {noop} to node which doesn't add any test to
	// generated rule.
	if prefix, _ := bintree.Mask.Size(); prefix == 0 {
		bintree.noop = true
	}

	//	debugBintree(bintree, "")
	return bintree
}

func (tree *NetBintree) Hi() NPBintree {
	if hi := tree.hi; hi != nil {
		return hi
	} else {
		return nil
	}
}
func (tree *NetBintree) Lo() NPBintree {
	if lo := tree.lo; lo != nil {
		return lo
	} else {
		return nil
	}
}
func (tree *NetBintree) Seq() []*PrtBintree { return nil }
func (tree *NetBintree) Subtree() NPBintree {
	if subtree := tree.subtree; subtree != nil {
		return subtree
	} else {
		return nil
	}
}
func (tree *NetBintree) Noop() bool { return tree.noop }

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

type PrtBintree struct {
	Proto
	subtree NPBintree
	hi      *PrtBintree
	lo      *PrtBintree
	seq     []*PrtBintree
	noop    bool
}

func genPrtBintree(
	elements []*Proto,
	tree LruleTree,
	tree2bintree map[*LruleTree]NPBintree) *PrtBintree {
	var ipPrt *Proto
	topPrt := make(map[string][]*Proto)
	subPrt := make(map[*Proto][]*Proto)

	// Add all protocols directly below protocol 'ip' into map topPrt
	// grouped by protocol. Add protocols below top protocols or below
	// other protocols of current set of protocols to map subPrt.
PRT:
	for _, prt := range elements {
		proto := prt.proto
		if proto == "ip" {
			ipPrt = prt
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
					subPrt[up] = append(subPrt[up], prt)
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
		topPrt[key] = append(topPrt[key], prt)
	}

	// Collect subtrees for tcp, udp, proto and icmp.
	var seq []*PrtBintree

	//Build subtree of tcp and udp protocols.
	//
	// We need not to handle 'tcp established' because it is only used
	// for stateless routers, but iptables is stateful.
	var genLohitrees func(prtAref []*Proto) (*PrtBintree, *PrtBintree)
	var genRangetree func(prtAref []*Proto) *PrtBintree
	genLohitrees = func(prtAref []*Proto) (*PrtBintree, *PrtBintree) {
		switch len(prtAref) {
		case 0:
			return nil, nil
		case 1:
			prt := prtAref[0]
			lo, hi := genLohitrees(subPrt[prt])
			node := &PrtBintree{
				Proto:   *prt,
				subtree: tree2bintree[tree[prt]],
				lo:      lo,
				hi:      hi,
			}
			return node, nil
		default:
			ports := make([]*Proto, len(prtAref))
			copy(ports, prtAref)
			sort.Slice(ports, func(i, j int) bool {
				return ports[i].ports[0] < ports[j].ports[0]
			})

			// Split array in two halves (prefer larger left part).
			mid := (len(ports)-1)/2 + 1
			left := ports[:mid]
			right := ports[mid:]
			return genRangetree(left), genRangetree(right)
		}
	}
	genRangetree = func(prtAref []*Proto) *PrtBintree {
		lo, hi := genLohitrees(prtAref)
		if hi == nil {
			return lo
		}

		// Take low port from lower tree and high port from high tree.
		prt := *prtAref[0]
		prt.ports = [2]int{lo.ports[0], hi.ports[1]}

		// Merge adjacent port ranges.
		if lo.ports[1]+1 == hi.ports[0] &&
			lo.subtree != nil && hi.subtree != nil && lo.subtree == hi.subtree {

			hilo := make([]*PrtBintree, 0, 4)
			for _, what := range []*PrtBintree{lo.lo, lo.hi, hi.lo, hi.hi} {
				if what != nil {
					hilo = append(hilo, what)
				}
			}
			if len(hilo) <= 2 {

				//		debug("Merged: $lo->{range}->[0]-$lo->{range}->[1]",
				//		      " $hi->{range}->[0]-$hi->{range}->[1]");
				node := &PrtBintree{
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
		return &PrtBintree{
			Proto: prt,
			lo:    lo,
			hi:    hi,
		}
	}
	for _, what := range []string{"tcp", "udp"} {
		if aref, ok := topPrt[what]; ok {
			seq = append(seq, genRangetree(aref))
		}
	}

	// Add single nodes for numeric protocols.
	if aref, ok := topPrt["proto"]; ok {
		sort.Slice(aref, func(i, j int) bool {
			return aref[i].proto < aref[j].proto
		})
		for _, prt := range aref {
			node := &PrtBintree{Proto: *prt, subtree: tree2bintree[tree[prt]]}
			seq = append(seq, node)
		}
	}

	// Build subtree of icmp protocols.
	if icmpAref, ok := topPrt["icmp"]; ok {
		type2prt := make(map[int][]*Proto)
		var icmpAny *Proto

		// If one protocol is 'icmp any' it is the only top protocol,
		// all other icmp protocols are sub protocols.
		if icmpAref[0].icmpType == -1 {
			icmpAny = icmpAref[0]
			icmpAref = subPrt[icmpAny]
		}

		// Process icmp protocols having defined type and possibly defined code.
		// Group protocols by type.
		for _, prt := range icmpAref {
			icmpType := prt.icmpType
			type2prt[icmpType] = append(type2prt[icmpType], prt)
		}

		// Parameter is array of icmp protocols all having
		// the same type and different but defined code.
		// Return reference to array of nodes sorted by code.
		genIcmpTypeCodeSorted := func(aref []*Proto) []*PrtBintree {
			sort.Slice(aref, func(i, j int) bool {
				return aref[i].icmpCode < aref[j].icmpCode
			})
			result := make([]*PrtBintree, len(aref))
			for i, proto := range aref {
				result[i] = &PrtBintree{
					Proto:   *proto,
					subtree: tree2bintree[tree[proto]],
				}
			}
			return result
		}

		// For collecting subtrees of icmp subtree.
		var seq2 []*PrtBintree

		// Process grouped icmp protocols having the same type.
		types := make([]int, 0, len(type2prt))
		for icmpType := range type2prt {
			types = append(types, icmpType)
		}
		sort.Ints(types)
		for _, icmpType := range types {
			aref2 := type2prt[icmpType]
			var node2 *PrtBintree

			// If there is more than one protocol,
			// all have same type and defined code.
			if len(aref2) > 1 {
				seq3 := genIcmpTypeCodeSorted(aref2)

				// Add a node 'icmp type any' as root.
				node2 = &PrtBintree{
					Proto: Proto{proto: "icmp", icmpType: icmpType, icmpCode: -1},
					seq:   seq3,
				}
			} else {

				// One protocol 'icmp type any'.
				prt := aref2[0]
				node2 = &PrtBintree{
					Proto:   *prt,
					subtree: tree2bintree[tree[prt]],
				}
				if aref3, ok := subPrt[prt]; ok {
					node2.seq = genIcmpTypeCodeSorted(aref3)
				}
			}
			seq2 = append(seq2, node2)
		}

		// Add root node for icmp subtree.
		var node *PrtBintree
		if icmpAny != nil {
			node = &PrtBintree{
				Proto:   *icmpAny,
				seq:     seq2,
				subtree: tree2bintree[tree[icmpAny]],
			}
		} else if len(seq2) > 1 {
			node = &PrtBintree{
				Proto: Proto{proto: "icmp", icmpType: -1, icmpCode: -1},
				seq:   seq2,
			}
		} else {
			node = seq2[0]
		}
		seq = append(seq, node)
	}

	// Add root node for whole tree.
	var bintree *PrtBintree
	if ipPrt != nil {
		bintree = &PrtBintree{
			Proto:   *ipPrt,
			seq:     seq,
			subtree: tree2bintree[tree[ipPrt]],
		}
	} else if len(seq) > 1 {
		bintree = &PrtBintree{Proto: Proto{proto: "ip"}, seq: seq}
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

func (tree *PrtBintree) Hi() NPBintree {
	if hi := tree.hi; hi != nil {
		return hi
	} else {
		return nil
	}
}
func (tree *PrtBintree) Lo() NPBintree {
	if lo := tree.lo; lo != nil {
		return lo
	} else {
		return nil
	}
}
func (tree *PrtBintree) Seq() []*PrtBintree { return tree.seq }
func (tree *PrtBintree) Subtree() NPBintree {
	if subtree := tree.subtree; subtree != nil {
		return subtree
	} else {
		return nil
	}
}
func (tree *PrtBintree) Noop() bool { return tree.noop }

type Order [4]struct {
	count int
	get   func(*Rule) interface{}
	set   func(*LinuxRule, interface{})
	name  string
}
type Chain struct {
	name  string
	rules LinuxRules
}
type NPBintree interface {
	Hi() NPBintree
	Lo() NPBintree
	Seq() []*PrtBintree
	Subtree() NPBintree
	Noop() bool
}

type LinuxRule struct {
	deny          bool
	src, dst      *NetBintree
	prt, srcRange *PrtBintree
	chain         *Chain
	useGoto       bool
}

type LinuxRules []*LinuxRule

func (rules *LinuxRules) push(rule *LinuxRule) {
	*rules = append(*rules, rule)
}

func findChains(aclInfo *ACLInfo, routerData *RouterData) {
	rules := aclInfo.rules
	prt2obj := aclInfo.prt2obj
	prtIP := prt2obj["ip"]
	prtIcmp := prt2obj["icmp"]
	prtTCP := prt2obj["tcp 1 65535"]
	prtUDP := prt2obj["udp 1 65535"]
	network00 := aclInfo.network00

	// Specify protocols tcp, udp, icmp in
	// {srcRange}, to get more efficient chains.
	for _, rule := range rules {
		srcRange := rule.srcRange
		if srcRange == nil {
			switch rule.prt.proto {
			case "tcp":
				srcRange = prtTCP
			case "udp":
				srcRange = prtUDP
			case "icmp":
				srcRange = prtIcmp
			default:
				srcRange = prtIP
			}
		}
		rule.srcRange = srcRange
	}

	//    my $printTree;
	//    $printTree = sub {
	//        my ($tree, $order, $depth) = @_;
	//        for my $name (keys %$tree) {
	//
	//            debug(' ' x $depth, $name);
	//            if ($depth < $#$order) {
	//                $printTree->($tree->{$name}, $order, $depth + 1);
	//            }
	//        }
	//    };

	codedLpermit := &LruleTree{false: nil}
	codedLdeny := &LruleTree{true: nil}
	codedBpermit := &NetBintree{noop: false}
	codedBdeny := &NetBintree{noop: true}
	subtree2bintree := make(map[*LruleTree]NPBintree)
	subtree2bintree[codedLdeny] = codedBdeny
	subtree2bintree[codedLpermit] = codedBpermit

	insertBintree := func(tree *LruleTree) NPBintree {
		var elem1 interface{}
		for key := range *tree {
			elem1 = key
			break
		}
		switch elem1.(type) {
		case *ipNet:
			elements := make([]*ipNet, 0, len(*tree))
			for key := range *tree {
				elements = append(elements, key.(*ipNet))
			}

			// Put prt/src/dst objects at the root of some subtree into a
			// (binary) tree. This is used later to convert subsequent tests
			// for ip/mask or port ranges into more efficient nested chains.
			return genAddrBintree(elements, *tree, subtree2bintree)
		case *Proto:
			elements := make([]*Proto, 0, len(*tree))
			for key := range *tree {
				elements = append(elements, key.(*Proto))
			}
			return genPrtBintree(elements, *tree, subtree2bintree)
		}
		return nil
	}

	// Used by $mergeSubtrees1 to find identical subtrees.
	// Use hash for efficient lookup.
	type lookup struct {
		depth int
		size  int
	}
	depth2size2subtrees := make(map[lookup][]*LruleTree)

	// Find and merge identical subtrees.
	// Create bintree from subtree and store in subtree2bintree.
	mergeSubtrees1 := func(tree *LruleTree, depth int) {

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
			bintree := insertBintree(subtree)
			subtree2bintree[subtree] = bintree
		}
	}

	mergeSubtrees := func(tree *LruleTree) NPBintree {

		// Process leaf nodes first.
		for _, tree1 := range *tree {
			for _, tree2 := range *tree1 {
				mergeSubtrees1(tree2, 2)
			}
		}

		// Process nodes next to leaf nodes.
		for _, tree1 := range *tree {
			mergeSubtrees1(tree1, 1)
		}

		// Process nodes next to root.
		mergeSubtrees1(tree, 0)
		return insertBintree(tree)
	}

	// Add new chain to current router.
	newChain := func(rules LinuxRules) *Chain {
		routerData.chainCounter++
		chain := &Chain{
			name:  fmt.Sprintf("c%d", routerData.chainCounter),
			rules: rules,
		}
		routerData.chains = append(routerData.chains, chain)
		return chain
	}

	getSeq := func(bintree NPBintree) []NPBintree {
		seq := bintree.Seq()
		var result []NPBintree
		if seq == nil {
			if hi := bintree.Hi(); hi != nil {
				result = append(result, hi)
			}
			if lo := bintree.Lo(); lo != nil {
				result = append(result, lo)
			}
		} else {
			result = make([]NPBintree, len(seq))
			for i, v := range seq {
				result[i] = v
			}
		}
		return result
	}

	cache := make(map[NPBintree]LinuxRules)

	var genChain func(tree NPBintree, order *Order, depth int) LinuxRules
	genChain = func(tree NPBintree, order *Order, depth int) LinuxRules {
		setter := order[depth].set
		var newRules LinuxRules

		// We need the original value later.
		bintree := tree
		for {
			seq := getSeq(bintree)
			subtree := bintree.Subtree()
			if subtree != nil {
				/*
				   if($order->[$depth+1]&&
				      $order->[$depth+1] =~ /^(src|dst)$/) {
				       debug($order->[$depth+1]);
				       debugBintree($subtree);
				   }
				*/
				rules := cache[subtree]
				if rules == nil {
					if depth+1 >= len(order) {
						rules = LinuxRules{{deny: subtree.(*NetBintree).noop}}
					} else {
						rules = genChain(subtree, order, depth+1)
					}
					if len(rules) > 1 && !bintree.Noop() {
						chain := newChain(rules)
						rules = LinuxRules{{chain: chain, useGoto: true}}
					}
					cache[subtree] = rules
				}

				// Don't use "goto", if some tests for sub-nodes of
				// subtree are following.
				if len(seq) != 0 || !bintree.Noop() {
					for _, rule := range rules {

						// Create a copy of each rule because we must not change
						// the original cached rules.
						newRule := *rule
						if len(seq) != 0 {
							newRule.useGoto = false
						}
						if !bintree.Noop() {
							setter(&newRule, bintree)
						}
						newRules = append(newRules, &newRule)
					}
				} else {
					newRules = append(newRules, rules...)
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
				rules := genChain(node, order, depth)
				newRules = append(newRules, rules...)
			}
		}
		if len(newRules) > 1 && !tree.Noop() {

			// Generate new chain. All elements of @seq are
			// known to be disjoint. If one element has matched
			// and branched to a chain, then the other elements
			// need not be tested again. This is implemented by
			// calling the chain using '-g' instead of the usual '-j'.
			chain := newChain(newRules)
			newRule := &LinuxRule{chain: chain, useGoto: true}
			setter(newRule, tree)
			return LinuxRules{newRule}
		} else {
			return newRules
		}
	}

	// Build rule trees. Generate and process separate tree for
	// adjacent rules with same 'deny' attribute.
	// Store rule tree together with order of attributes.
	type treeAndOrder struct {
		tree  *LruleTree
		order *Order
	}
	var ruleSets []treeAndOrder
	var count [4]map[interface{}]int
	for i, _ := range count {
		count[i] = make(map[interface{}]int)
	}
	order := Order{
		{
			get: func(rule *Rule) interface{} { return rule.srcRange },
			set: func(rule *LinuxRule, val interface{}) {
				rule.srcRange = val.(*PrtBintree)
			},
			name: "srcRange",
		},
		{
			get: func(rule *Rule) interface{} { return rule.dst },
			set: func(rule *LinuxRule, val interface{}) {
				rule.dst = val.(*NetBintree)
			},
			name: "dst",
		},
		{
			get: func(rule *Rule) interface{} { return rule.prt },
			set: func(rule *LinuxRule, val interface{}) {
				rule.prt = val.(*PrtBintree)
			},
			name: "prt",
		},
		{
			get: func(rule *Rule) interface{} { return rule.src },
			set: func(rule *LinuxRule, val interface{}) {
				rule.src = val.(*NetBintree)
			},
			name: "src",
		},
	}
	if len(rules) > 0 {
		prevDeny := rules[0].deny

		// Add special rule as marker, that end of rules has been reached.
		rules.push(&Rule{src: nil})
		var start int = 0
		last := len(rules) - 1
		var i int = 0
		for {
			rule := rules[i]
			deny := rule.deny
			if deny == prevDeny && i < last {

				// Count, which attribute has the largest number of
				// different values.
				for i, what := range order {
					count[i][what.get(rule)]++
				}
				i++
			} else {
				for i, attrMap := range count {
					order[i].count = len(attrMap)

					// Reset counter for next tree.
					count[i] = make(map[interface{}]int)
				}

				// Use key with smaller number of different values
				// first in rule tree. This gives smaller tree and
				// fewer tests in chains.
				sort.SliceStable(order[:], func(i, j int) bool {
					return order[i].count < order[j].count
				})
				ruleTree := make(LruleTree)
				for _, rule := range rules[start:i] {
					add := func(what int, tree *LruleTree) *LruleTree {
						key := order[what].get(rule)
						subtree := (*tree)[key]
						if subtree == nil {
							m := make(LruleTree)
							(*tree)[key] = &m
							subtree = &m
						}
						return subtree
					}
					subtree := add(0, &ruleTree)
					subtree = add(1, subtree)
					subtree = add(2, subtree)
					key3 := order[3].get(rule)
					if rule.deny {
						(*subtree)[key3] = codedLdeny
					} else {
						(*subtree)[key3] = codedLpermit
					}
				}

				//for _, what := range order {
				//   toStderr(what.name)
				//}
				ruleSets = append(ruleSets, treeAndOrder{&ruleTree, &order})
				if i == last {
					break
				}
				start = i
				prevDeny = deny
			}
		}
		rules = nil
	}

	var lrules LinuxRules
	for i, set := range ruleSets {

		//    $printTree->($tree, $order, 0);
		bintree := mergeSubtrees(set.tree)
		result := genChain(bintree, set.order, 0)

		// Goto must not be used in last rule of rule tree which is
		// not the last tree.
		if i < len(ruleSets)-1 {
			rule := result[len(result)-1]
			rule.useGoto = false
		}

		// Postprocess lrules: Add missing attributes prt, src, dst
		// with no-op values.
		for _, rule := range result {
			if rule.src == nil {
				rule.src = &NetBintree{ipNet: *network00}
			}
			if rule.dst == nil {
				rule.dst = &NetBintree{ipNet: *network00}
			}
			prt := rule.prt
			srcRange := rule.srcRange
			if prt == nil && srcRange == nil {
				rule.prt = &PrtBintree{Proto: *prtIP}
			} else if prt == nil {
				switch srcRange.proto {
				case "tcp":
					rule.prt = &PrtBintree{Proto: *prtTCP}
				case "udp":
					rule.prt = &PrtBintree{Proto: *prtUDP}
				case "icmp":
					rule.prt = &PrtBintree{Proto: *prtIcmp}
				default:
					rule.prt = &PrtBintree{Proto: *prtIP}
				}
			}
		}
		lrules = append(lrules, result...)
	}
	aclInfo.lrules = lrules
}

// Given an IP and mask, return its address
// as "x.x.x.x/x" or "x.x.x.x" if prefix == 32 (128 for IPv6).
func prefixCode(ipNet *ipNet) string {
	size, bits := ipNet.Mask.Size()
	if size == bits {
		return ipNet.IP.String()
	} else {
		return ipNet.String()
	}
}

func actionCode(rule *LinuxRule) (result string) {
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
func printChains(fd *os.File, routerData *RouterData) {
	chains := routerData.chains
	routerData.chains = nil
	if len(chains) == 0 {
		return
	}

	aclInfo := routerData.acls[0]
	prt2obj := aclInfo.prt2obj
	prtIP := prt2obj["ip"]
	prtIcmp := prt2obj["icmp"]
	prtTCP := prt2obj["tcp 1 65535"]
	prtUDP := prt2obj["udp 1 65535"]

	// Declare chain names.
	for _, chain := range chains {
		fmt.Fprintf(fd, ":%s -\n", chain.name)
	}

	// Define chains.
	for _, chain := range chains {
		prefix := fmt.Sprintf("-A %s", chain.name)
		for _, rule := range chain.rules {
			var jump string
			if rule.useGoto {
				jump = "-g"
			} else {
				jump = "-j"
			}
			result := fmt.Sprintf("%s %s", jump, actionCode(rule))
			if src := rule.src; src != nil {
				if size, _ := src.Mask.Size(); size != 0 {
					result += " -s " + prefixCode(&src.ipNet)
				}
			}
			if dst := rule.dst; dst != nil {
				if size, _ := dst.Mask.Size(); size != 0 {
					result += " -d " + prefixCode(&dst.ipNet)
				}
			}
			srcRange := rule.srcRange
			prt := rule.prt
			switch {
			case srcRange == nil && prt == nil:
				// break
			case prt != nil && prt.Proto.proto == "ip":
				// break
			case prt == nil:
				if srcRange.Proto.proto == "ip" {
					break
				}
				prt = new(PrtBintree)
				switch srcRange.Proto.proto {
				case "tcp":
					prt.Proto = *prtTCP
				case "udp":
					prt.Proto = *prtUDP
				case "icmp":
					prt.Proto = *prtIcmp
				default:
					prt.Proto = *prtIP
				}
				fallthrough
			default:
				result += " " + iptablesPrtCode(srcRange, prt)
			}
			fmt.Fprintln(fd, prefix, result)
		}
	}

	// Empty line as delimiter.
	fmt.Fprintln(fd)
}

func iptablesACLLine(fd *os.File, rule *LinuxRule, prefix string) {
	src, dst, srcRange, prt := rule.src, rule.dst, rule.srcRange, rule.prt
	var jump string
	if rule.useGoto {
		jump = "-g"
	} else {
		jump = "-j"
	}
	result := fmt.Sprintf("%s %s %s", prefix, jump, actionCode(rule))
	if size, _ := src.Mask.Size(); size != 0 {
		result += " -s " + prefixCode(&src.ipNet)
	}
	if size, _ := dst.Mask.Size(); size != 0 {
		result += " -d " + prefixCode(&dst.ipNet)
	}
	if prt.proto != "ip" {
		result += " " + iptablesPrtCode(srcRange, prt)
	}
	fmt.Fprintln(fd, result)
}

func printIptablesACL(fd *os.File, aclInfo *ACLInfo) {
	name := aclInfo.name
	fmt.Fprintf(fd, ":%s -\n", name)
	intfPrefix := fmt.Sprintf("-A %s", name)
	for _, rule := range aclInfo.lrules {
		iptablesACLLine(fd, rule, intfPrefix)
	}
}

func convertRuleObjects(rules []*jRule, ipNet2obj name2ipNet, prt2obj name2Proto) (Rules, bool) {
	if rules == nil {
		return nil, false
	}
	var expanded Rules
	var hasLog bool
	for _, rule := range rules {
		srcList := ipNetList(rule.Src, ipNet2obj)
		dstList := ipNetList(rule.Dst, ipNet2obj)
		prtList := prtList(rule.Prt, prt2obj)
		var srcRange *Proto
		if rule.SrcRange != "" {
			srcRange = prt(rule.SrcRange, prt2obj)
		}
		hasLog = hasLog || rule.Log != ""
		for _, src := range srcList {
			for _, dst := range dstList {
				for _, prt := range prtList {
					expanded.push(
						&Rule{
							deny:         rule.Deny == 1,
							src:          src,
							dst:          dst,
							srcRange:     srcRange,
							prt:          prt,
							log:          rule.Log,
							optSecondary: rule.OptSecondary == 1,
						})
				}
			}
		}
	}
	return expanded, hasLog
}

type RouterData struct {
	model           string
	acls            []*ACLInfo
	logDeny         string
	filterOnlyGroup *ipNet
	doObjectgroup   bool
	objGroupsHash   map[groupKey][]*ObjGroup
	objGroupCounter int
	chainCounter    int
	chains          []*Chain
}

func ipNetList(names []string, ipNet2obj name2ipNet) []*ipNet {
	result := make([]*ipNet, len(names))
	for i, name := range names {
		obj, ok := ipNet2obj[name]
		if !ok {
			obj = createIPObj(name)
			ipNet2obj[name] = obj
		}
		result[i] = obj
	}
	return result
}

func prt(name string, prt2obj name2Proto) *Proto {
	obj, ok := prt2obj[name]
	if !ok {
		obj = createPrtObj(name)
		prt2obj[name] = obj
	}
	return obj
}

func prtList(names []string, prt2obj name2Proto) []*Proto {
	result := make([]*Proto, len(names))
	for i, name := range names {
		result[i] = prt(name, prt2obj)
	}
	return result
}

//go:generate easyjson Pass2.go
//easyjson:json
type jRouterData struct {
	Model         string     `json:"model"`
	ACLs          []jACLInfo `json:"acls"`
	FilterOnly    []string   `json:"filter_only"`
	DoObjectgroup int        `json:"do_objectgroup"`
	LogDeny       string     `json:"log_deny"`
}
type jACLInfo struct {
	Name         string   `json:"name"`
	IsStdACL     int      `json:"is_std_acl"`
	IntfRules    []*jRule `json:"intf_rules"`
	Rules        []*jRule `json:"rules"`
	OptNetworks  []string `json:"opt_networks"`
	NoOptAddrs   []string `json:"no_opt_addrs"`
	NeedProtect  []string `json:"need_protect"`
	FilterAnySrc int      `json:"filter_any_src"`
	IsCryptoACL  int      `json:"is_crypto_acl"`
	AddPermit    int      `json:"add_permit"`
	AddDeny      int      `json:"add_deny"`
}
type jRule struct {
	Deny         int      `json:"deny"`
	Src          []string `json:"src"`
	Dst          []string `json:"dst"`
	Prt          []string `json:"prt"`
	SrcRange     string   `json:"src_range"`
	Log          string   `json:"log"`
	OptSecondary int      `json:"opt_secondary"`
}

func prepareACLs(path string) *RouterData {
	var jdata jRouterData
	routerData := new(RouterData)
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
	routerData.model = model
	routerData.logDeny = jdata.LogDeny
	doObjectgroup := jdata.DoObjectgroup == 1
	routerData.doObjectgroup = doObjectgroup
	rawACLs := jdata.ACLs
	acls := make([]*ACLInfo, len(rawACLs))
	for i, rawInfo := range rawACLs {

		// Process networks and protocols of each interface individually,
		// because relation between networks may be changed by NAT.
		ipNet2obj := make(name2ipNet)
		prt2obj := make(name2Proto)

		intfRules, hasLog1 := convertRuleObjects(
			rawInfo.IntfRules, ipNet2obj, prt2obj)
		rules, hasLog2 := convertRuleObjects(
			rawInfo.Rules, ipNet2obj, prt2obj)

		filterOnly := ipNetList(jdata.FilterOnly, ipNet2obj)

		optNetworks := ipNetList(rawInfo.OptNetworks, ipNet2obj)
		for _, obj := range optNetworks {
			obj.optNetworks = obj
		}
		noOptAddrs := ipNetList(rawInfo.NoOptAddrs, ipNet2obj)
		for _, obj := range noOptAddrs {
			obj.noOptAddrs = true
		}
		needProtect := ipNetList(rawInfo.NeedProtect, ipNet2obj)
		for _, obj := range needProtect {
			obj.needProtect = true
		}
		setupIPNetRelation(ipNet2obj, ipv6)

		aclInfo := &ACLInfo{
			name:         rawInfo.Name,
			isStdACL:     rawInfo.IsStdACL == 1,
			intfRules:    intfRules,
			rules:        rules,
			prt2obj:      prt2obj,
			ipNet2obj:    ipNet2obj,
			filterOnly:   filterOnly,
			optNetworks:  optNetworks,
			noOptAddrs:   noOptAddrs,
			filterAnySrc: rawInfo.FilterAnySrc == 1,
			needProtect:  needProtect,
			network00:    ipNet2obj[getNet00Addr(ipv6)],
		}
		acls[i] = aclInfo

		if len(needProtect) > 0 {
			markSupernetsOfNeedProtect(needProtect)
		}
		if model == "Linux" {
			addTCPUDPIcmp(prt2obj)
		}

		setupPrtRelation(prt2obj)
		aclInfo.prtIP = prt2obj["ip"]

		if model == "Linux" {
			findChains(aclInfo, routerData)
		} else {
			intfRules = optimizeRules(intfRules, aclInfo)
			intfRules = joinRanges(intfRules, prt2obj)
			rules = optimizeRules(rules, aclInfo)

			// Join adjacent port ranges. This must be called after
			// local optimization, because protocols will be
			// overlapping again after joining.
			rules = joinRanges(rules, prt2obj)
			aclInfo.intfRules = moveRulesEspAh(intfRules, prt2obj, hasLog1)
			aclInfo.rules = moveRulesEspAh(rules, prt2obj, hasLog2)

			hasFinalPermit := checkFinalPermit(aclInfo)
			addPermit := rawInfo.AddPermit == 1
			addDeny := rawInfo.AddDeny == 1
			addProtectRules(aclInfo, hasFinalPermit || addPermit)
			if doObjectgroup && rawInfo.IsCryptoACL != 1 {
				findObjectgroups(aclInfo, routerData)
			}
			if len(filterOnly) > 0 && !addPermit {
				addLocalDenyRules(aclInfo, routerData)
			} else if !hasFinalPermit {
				addFinalPermitDenyRule(aclInfo, addDeny, addPermit)
			}
		}
	}
	routerData.acls = acls
	return routerData
}

// Given IP or group object, return its address in Cisco syntax.
func ciscoACLAddr(obj *ipNet, model string) string {

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
		ipCode := ip.String()
		if prefix == bits {
			return "host " + ipCode
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
			maskCode := mask.String()
			return ipCode + " " + maskCode
		}
	}
}

func printObjectGroups(fd *os.File, aclInfo *ACLInfo, model string) {
	groups := aclInfo.objectGroups
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
				fatalErr("Unexpected network with mask 0 in object-group")
			}
			adr := ciscoACLAddr(element, model)
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
func ciscoPrtCode(srcRange, prt *Proto) (t1, t2, t3 string) {
	proto := prt.proto

	switch proto {
	case "ip":
		return "ip", "", ""
	case "tcp", "udp":
		portCode := func(rangeObj *Proto) string {
			ports := rangeObj.ports
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
		dstPrt := portCode(prt)
		if prt.established {
			if dstPrt != "" {
				dstPrt += " established"
			} else {
				dstPrt = "established"
			}
		}
		var srcPrt string
		if srcRange != nil {
			srcPrt = portCode(srcRange)
		}
		return proto, srcPrt, dstPrt
	case "icmp":
		icmpType := prt.icmpType
		if icmpType != -1 {
			code := prt.icmpCode
			if code != -1 {
				return proto, "", fmt.Sprint(icmpType, code)
			} else {
				return proto, "", fmt.Sprint(icmpType)
			}
		} else {
			return proto, "", ""
		}
	default:
		return proto, "", ""
	}
}

func getCiscoAction(deny bool) string {
	if deny {
		return "deny"
	} else {
		return "permit"
	}
}

func printAsaStdACL(fd *os.File, aclInfo *ACLInfo, model string) {
	for _, rule := range aclInfo.rules {
		fmt.Fprintln(
			fd,
			"access-list",
			aclInfo.name,
			"standard",
			getCiscoAction(rule.deny),
			ciscoACLAddr(rule.src, model))
	}
}

func printCiscoACL(fd *os.File, aclInfo *ACLInfo, routerData *RouterData) {
	model := routerData.model

	if aclInfo.isStdACL {
		printAsaStdACL(fd, aclInfo, model)
		return
	}

	name := aclInfo.name
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

	for _, rules := range []Rules{aclInfo.intfRules, aclInfo.rules} {
		for _, rule := range rules {
			action := getCiscoAction(rule.deny)
			protoCode, srcPortCode, dstPortCode :=
				ciscoPrtCode(rule.srcRange, rule.prt)
			result := fmt.Sprintf("%s %s %s", prefix, action, protoCode)
			result += " " + ciscoACLAddr(rule.src, model)
			if srcPortCode != "" {
				result += " " + srcPortCode
			}
			result += " " + ciscoACLAddr(rule.dst, model)
			if dstPortCode != "" {
				result += " " + dstPortCode
			}

			if rule.log != "" {
				result += " " + rule.log
			} else if rule.deny && routerData.logDeny != "" {
				result += " " + routerData.logDeny
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

func printACL(fd *os.File, aclInfo *ACLInfo, routerData *RouterData) {
	model := routerData.model
	if model == "Linux" {

		// Print all sub-chains at once before first toplevel chain is printed.
		printChains(fd, routerData)
		printIptablesACL(fd, aclInfo)
	} else {
		printObjectGroups(fd, aclInfo, model)
		printCiscoACL(fd, aclInfo, routerData)
	}
}

func printCombined(config []string, routerData *RouterData, outPath string) {
	fd, err := os.Create(outPath)
	if err != nil {
		fatalErr("Can't open %s for writing: %v", outPath, err)
	}
	aclHash := make(map[string]*ACLInfo)
	for _, acl := range routerData.acls {
		aclHash[acl.name] = acl
	}

	// Print config and insert printed ACLs at "#insert <name>" markers.
	re := regexp.MustCompile("^#insert (.*)$")
	for _, line := range config {

		indexes := re.FindStringSubmatchIndex(line)

		if indexes != nil {
			// Print ACL.
			name := line[indexes[2]:indexes[3]]
			aclInfo, found := aclHash[name]
			if !found {
				fatalErr("Unexpected ACL %s", name)
			}
			printACL(fd, aclInfo, routerData)
		} else {
			// Print unchanged config line.
			fmt.Fprintln(fd, line)
		}
	}

	if err := fd.Close(); err != nil {
		fatalErr("Can't close %s: %v", outPath, err)
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
func tryPrev(devicePath, dir, prev string) bool {
	if !isDir(prev) {
		return false
	}
	prevFile := prev + "/" + devicePath
	if !isRegular(prevFile) {
		return false
	}
	codeFile := dir + "/" + devicePath
	for _, ext := range [...]string{"config", "rules"} {
		pass1name := codeFile + "." + ext
		pass1prev := prevFile + "." + ext
		if !isRegular(pass1prev) {
			return false
		}
		cmd := exec.Command("cmp", "-s", pass1name, pass1prev)
		if cmd.Run() != nil {
			return false
		}
	}
	cmd := exec.Command("cp", "-p", prevFile, codeFile)
	if cmd.Run() != nil {
		return false
	}

	// File was found and copied successfully.
	diagMsg("Reused .prev/" + devicePath)
	return true
}

func readFileLines(filename string) []string {
	fd, err := os.Open(filename)
	if err != nil {
		fatalErr("Can't open %s for reading: %v", filename, err)
	}
	result := make([]string, 0)
	scanner := bufio.NewScanner(fd)
	for scanner.Scan() {
		line := scanner.Text()
		result = append(result, line)
	}
	if err := scanner.Err(); err != nil {
		fatalErr("While reading device names: %v", err)
	}
	return result
}

func pass2File(devicePath, dir string, c chan bool) {
	success := false

	// Send ok on success
	defer func() { c <- success }()

	file := dir + "/" + devicePath
	routerData := prepareACLs(file + ".rules")
	config := readFileLines(file + ".config")
	printCombined(config, routerData, file)
	success = true
}

func applyConcurrent(deviceNamesFh *os.File, dir, prev string) {

	var started, generated, reused, errors int
	concurrent := config.concurrent
	c := make(chan bool, concurrent)
	workersLeft := concurrent

	waitAndCheck := func() {
		if <-c {
			generated++
		} else {
			errors++
		}
		started--
	}

	// Read to be processed files line by line.
	scanner := bufio.NewScanner(deviceNamesFh)
	for scanner.Scan() {
		devicePath := scanner.Text()

		if tryPrev(devicePath, dir, prev) {
			reused++
		} else if 1 >= concurrent {
			// Process sequentially.
			pass2File(devicePath, dir, c)
			waitAndCheck()
		} else if workersLeft > 0 {
			// Start concurrent jobs at beginning.
			go pass2File(devicePath, dir, c)
			workersLeft--
			started++
		} else {
			// Start next job, after some job has finished.
			waitAndCheck()
			go pass2File(devicePath, dir, c)
			started++
		}
	}

	// Wait for all jobs to be finished.
	for started > 0 {
		waitAndCheck()
	}

	if err := scanner.Err(); err != nil {
		fatalErr("While reading device names: %v", err)
	}

	if errors > 0 {
		fatalErr("Failed")
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
	var fromPass1 *os.File
	if config.pipe {
		fromPass1 = os.Stdin
	} else {
		devlist := dir + "/.devlist"
		var err error
		fromPass1, err = os.Open(devlist)
		if err != nil {
			fatalErr("Can't open %s for reading: %v", devlist, err)
		}
	}

	applyConcurrent(fromPass1, dir, prev)

	// Remove directory '.prev' created by pass1
	// or remove symlink '.prev' created by newpolicy.pl.
	err := os.RemoveAll(prev)
	if err != nil {
		fatalErr("Can't remove %s: %v", prev, err)
	}
}

func main() {
	if len(os.Args) != 2 {
		fatalErr("Usage: %s DIR", os.Args[0])
	}
	var dir = os.Args[1]
	pass2(dir)
	info("Finished")
}
