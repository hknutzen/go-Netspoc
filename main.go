package main

import (
	"fmt"
	"io/ioutil"
	//	"github.com/davecgh/go-spew/spew"
	"github.com/Sereal/Sereal/Go/sereal"
	"net"
	"os"
	"strings"
)

var path = "/home/hk/out.sereal"

type xAny interface{}
type xMap = map[string]interface{}
type xArray = []interface{}

type someObj interface {
	network() *Network
	up() someObj
	setCommon(m xMap)
}
type pathObj interface{}

func convertBool(x xAny) bool {
	switch x.(type) {
	case nil:
		return false
	case string:
		b := x != "" && x != "0"
		return b
	default:
		return false
	}
}

func getString(x xAny) string {
	switch a := x.(type) {
	case string:
		return a
	case []byte:
		return string(a[:])
	case int:
		return fmt.Sprint(a)
	default:
		panic(fmt.Errorf("Expected string or byte slice but got %v", a))
	}
}
func convertStrings(x xAny) []string {
	a := getArray(x)
	result := make([]string, len(a))
	for i, elt := range a {
		result[i] = getString(elt)
	}
	return result
}

func getArray(x xAny) xArray {
	switch a := x.(type) {
	case xArray:
		return a
	case *xArray:
		return *a
	default:
		panic(fmt.Errorf("Expected xArray or *xArray but git %v", a))
	}
}

func getMap(x xAny) xMap {
	switch m := x.(type) {
	case xMap:
		return m
	case *xMap:
		return *m
	default:
		panic(fmt.Errorf("Expected xMap or *xMap but got %v", m))
	}
}

type IPObj struct {
	Name string
	IP   net.IP
	Up   someObj
}

func (x *IPObj) up() someObj { return x.Up }
func (x *IPObj) setCommon(m xMap) {
	x.Name = m["name"].(string)
	ip := m["ip"]
	if ip == nil {
		fmt.Println(x.Name)
	} else {
		x.IP = m["ip"].([]byte)
	}
	if up, ok := m["up"]; ok {
		x.Up = convertSomeObj(up)
	}
}

type Network struct {
	IPObj
	Mask       net.IPMask
	Subnets    []*Subnet
	Interfaces []*Interface
	zone       *Zone
}

func convertNetwork(x xAny) *Network {
	m := getMap(x)
	if n, ok := m["ref"]; ok {
		return n.(*Network)
	}
	n := new(Network)
	m["ref"] = n
	n.setCommon(m)
	if m["mask"] != nil {
		n.Mask = m["mask"].([]byte)
	}
	if list, ok := m["subnets"]; ok {
		xSubnets := list.(xArray)
		subnets := make([]*Subnet, len(xSubnets))
		for i, xSubnet := range xSubnets {
			subnets[i] = convertSubnet(xSubnet)
		}
		n.Subnets = subnets
	}
	if list, ok := m["interfaces"]; ok {
		xInterfaces := list.(xArray)
		interfaces := make([]*Interface, len(xInterfaces))
		for i, xInterface := range xInterfaces {
			interfaces[i] = convertInterface(xInterface)
		}
		n.Interfaces = interfaces
	}
	return n
}
func (x *Network) network() *Network { return x }

type NetObj struct {
	IPObj
	Network *Network
}
func (x *NetObj) setCommon(m xMap) {
	x.IPObj.setCommon(m)
	x.Network = convertNetwork(m["network"])
}
func (x *NetObj) network() *Network { return x.Network }

type Subnet struct {
	NetObj
	Mask    net.IPMask
}

func convertSubnet(x xAny) *Subnet {
	m := getMap(x)
	if s, ok := m["ref"]; ok {
		return s.(*Subnet)
	}
	s := new(Subnet)
	m["ref"] = s
	s.setCommon(m)
	s.Mask = m["mask"].([]byte)
	return s
}

type Router struct {
	Name       string
	Managed    string
	Interfaces []*Interface
}

func convertRouter(x xAny) *Router {
	m := getMap(x)
	if r, ok := m["ref"]; ok {
		return r.(*Router)
	}
	r := new(Router)
	m["ref"] = r
	r.Name = m["name"].(string)
	if list, ok := m["interfaces"]; ok {
		xInterfaces := list.(xArray)
		interfaces := make([]*Interface, len(xInterfaces))
		for i, xInterface := range xInterfaces {
			interfaces[i] = convertInterface(xInterface)
		}
		r.Interfaces = interfaces
	}
	return r
}

type Interface struct {
	NetObj
	Router  *Router
}

func convertInterface(x xAny) *Interface {
	m := getMap(x)
	if i, ok := m["ref"]; ok {
		return i.(*Interface)
	}
	i := new(Interface)
	m["ref"] = i
	i.setCommon(m)
	i.Router = convertRouter(m["router"])
	return i
}

func convertSomeObj(x xAny) someObj {
	m := getMap(x)
	if o, ok := m["ref"]; ok {
		return o.(someObj)
	}
	if _, ok := m["router"]; ok {
		return convertInterface(x)
	}
	if _, ok := m["network"]; ok {
		return convertSubnet(x)
	}
	return convertNetwork(x)
}

func convertSomeObjects(x xAny) []someObj {
	a := getArray(x)
	objects := make([]someObj, len(a))
	for i, x := range a {
		objects[i] = convertSomeObj(x)
	}
	return objects
}

type Zone struct {
	Name     string
	Networks []*Network
}

func convertZone(x xAny) *Zone {
	m := getMap(x)
	if r, ok := m["ref"]; ok {
		return r.(*Zone)
	}
	z := new(Zone)
	m["ref"] = z
	z.Name = m["name"].(string)
	if list, ok := m["networks"]; ok {
		xNetworks := list.(xArray)
		networks := make([]*Network, len(xNetworks))
		for i, xNetwork := range xNetworks {
			networks[i] = convertNetwork(xNetwork)
		}
		z.Networks = networks
	}
	return z
}

func convertPathObj(x xAny) pathObj {
	m := getMap(x)
	if o, ok := m["ref"]; ok {
		return o.(pathObj)
	}
	if _, ok := m["router"]; ok {
		return convertInterface(x)
	}
	if _, ok := m["managed"]; ok {
		return convertRouter(x)
	}
	return convertZone(x)
}

type modifiers struct {
	reversed             bool
	stateless            bool
	oneway               bool
	srcNet               bool
	dstNet               bool
	overlaps             bool
	noCheckSupernetRules bool
}

type proto struct {
	name        string
	proto       string
	ports       [2]int
	established bool
	icmpType    int
	icmpCode    int
	modifiers   modifiers
	up          *proto
	localUp     *proto
	hasNeighbor bool
}

func convertProto(x xAny) *proto {
	if x == nil {
		return nil
	}
	m := getMap(x)
	if o, ok := m["ref"]; ok {
		return o.(*proto)
	}
	p := new(proto)
	m["ref"] = p
	p.name = getString(m["name"])
	p.proto = getString(m["proto"])
	if list, ok := m["ports"]; ok {
		a := list.(xArray)
		p.ports = [2]int{a[0].(int), a[1].(int)}
	}
	if _, ok := m["established"]; ok {
		p.established = true
	}
	if t, ok := m["icmp_type"]; ok {
		p.icmpType = t.(int)
	}
	if c, ok := m["icmp_code"]; ok {
		p.icmpCode = c.(int)
	}
	if u, ok := m["up"]; ok {
		p.up = convertProto(u)
	}
	return p
}
func convertProtos(x xAny) []*proto {
	a := getArray(x)
	list := make([]*proto, len(a))
	for i, x := range a {
		list[i] = convertProto(x)
	}
	return list
}

var prtIP = &proto{name: "ip", proto: "ip"}

type Service struct {
	name             string
	ruleCount        int
	duplicateCount   int
	redundantCount   int
	hasSameDupl      map[*Service]bool
	Overlaps         []*Service
	overlapsUsed     map[*Service]bool
	srcRange2origPrt map[*proto]map[*proto]*proto
	prt2origPrt      map[*proto]*proto
}

// Discard intermediate original rule.
func convertSrvRule(x1 xAny) *Service {
	m1 := getMap(x1)
	x2 := m1["service"]
	m2 := getMap(x2)
	s := new(Service)
	s.name = m2["name"].(string)
	return s
}

type Rule struct {
	Deny          bool
	Src           []someObj
	Dst           []someObj
	Prt           []*proto
	SrcRange      *proto
	Service       *Service
	Log           string
	SrcPath       pathObj
	DstPath       pathObj
	Stateless     bool
	StatelessICMP bool
}

func convertRule(m xMap) *Rule {
	r := new(Rule)
	r.Deny = convertBool(m["deny"])
	r.Src = convertSomeObjects(m["src"])
	r.Dst = convertSomeObjects(m["dst"])
	r.Prt = convertProtos(m["prt"])
	r.SrcRange = convertProto(m["src_range"])
	r.SrcPath = convertPathObj(m["src_path"])
	r.DstPath = convertPathObj(m["dst_path"])
	if list, ok := m["log"]; ok {
		// Join for simpler comparison.
		// Tags must have been sorted already.
		r.Log = strings.Join(convertStrings(list), ",")
	}
	r.Stateless = convertBool(m["stateless"])
	r.StatelessICMP = convertBool(m["stateless_icmp"])
	r.Service = convertSrvRule(m["rule"])
	return r
}

func convertRules(a xArray) []*Rule {
	rules := make([]*Rule, len(a))
	for i, x := range a {
		rules[i] = convertRule(x.(xMap))
	}
	return rules
}

type PathRules struct {
	Permit []*Rule
	Deny   []*Rule
}

func convertPathRules(m xMap) *PathRules {
	rules := new(PathRules)
	if v := m["permit"]; v != nil {
		rules.Permit = convertRules(v.(xArray))
	}
	if v := m["deny"]; v != nil {
		rules.Deny = convertRules(v.(xArray))
	}
	return rules
}

var errorCounter int = 0

func checkAbort() {
	errorCounter++
	if errorCounter >= 10 {
		fmt.Fprintf(os.Stderr, "Aborted after %d errors\n", errorCounter)
		os.Exit(1)
	}
}

func errMsg(format string, args ...interface{}) {
	string := "Error: " + fmt.Sprintf(format, args...)
	fmt.Fprintln(os.Stderr, string)
	checkAbort()
}

func progress(s string) {
	fmt.Fprintln(os.Stderr, s)
}

type ExpandedRule struct {
	deny      bool
	stateless bool
	src       someObj
	dst       someObj
	srcRange  *proto
	prt       *proto
	log       string
	service   *Service
	redundant bool
}

func fillExpandedRule(rule *Rule) *ExpandedRule {
	return &ExpandedRule{
		deny:      rule.Deny,
		stateless: rule.Stateless,
		log:       rule.Log,
		srcRange:  rule.SrcRange,
		service:   rule.Service,
	}
}

func (r *Rule) printRule() {
	e := fillExpandedRule(r)
	e.src = r.Src[0]
	e.dst = r.Dst[0]
	e.prt = r.Prt[0]
	e.printRule()
}

func (r *ExpandedRule) printRule() string {
	extra := ""
	if r.log != "" {
		extra += " " + r.log
	}
	if r.stateless {
		extra += " stateless"
	}
	if r.service != nil {
		extra += " of " + r.service.name
	}
	var action string
	if r.deny {
		action = "deny"
	} else {
		action = "permit"
	}
	return fmt.Sprintf("%s src=%s; dst=%s; prt=%s;%s",
		action, r.src, r.dst, r.prt, extra)
}

func getOrigPrt(rule *ExpandedRule) *proto {
	prt := rule.prt
	srcRange := rule.srcRange
	service := rule.service
	var orig *proto
	if srcRange != nil {
		orig = service.srcRange2origPrt[srcRange][prt]
	} else {
		orig = service.prt2origPrt[prt]
	}
	if orig != nil {
		return orig
	} else {
		return prt
	}
}

/*########################################################################
# Expand rules and check them for redundancy
########################################################################*/

// Derive reduced 'local_up' relation from 'up' relation between protocols.
// Reduced relation has only protocols that are referenced in list of rules.
// New relation is used in findRedundantRules.
// We get better performance compared to original relation, because
// transient chain from some protocol to largest protocol becomes shorter.
func setLocalPrtRelation(rules []*Rule) {
	prtMap := make(map[*proto]bool)
	for _, rule := range rules {
		prtList := rule.Prt
		for _, prt := range prtList {
			prtMap[prt] = true
		}
	}
	for prt := range prtMap {
		var localUp *proto
		up := prt.up
		for up != nil {
			if prtMap[up] {
				localUp = up
				break
			}
			up = up.up
		}
		prt.localUp = localUp
	}
}

var duplicateRules [][2]*ExpandedRule

func collectDuplicaterules(rule, other *ExpandedRule) {
	service := rule.service

	// Mark duplicate rules in both services.

	// But count each rule only once. For duplicate rules, this can
	// only occur for rule other, because all identical rules are
	// compared with other. But we need to mark rule as well, because
	// it must only be counted once, if it is both duplicate and
	// redundandant.
	rule.redundant = true
	service.duplicateCount++
	oservice := other.service
	if !other.redundant {
		oservice.duplicateCount++
	}
	other.redundant = true

	// Link both services, so we later show only one of both service as
	// redundant.
	service.hasSameDupl[oservice] = true
	oservice.hasSameDupl[service] = true

	for _, overlap := range service.Overlaps {
		if oservice == overlap {
			service.overlapsUsed[overlap] = true
			return
		}
	}
	for _, overlap := range oservice.Overlaps {
		if service == overlap {
			oservice.overlapsUsed[overlap] = true
			return
		}
	}
	prt1 := getOrigPrt(rule)
	prt2 := getOrigPrt(other)
	if prt1.modifiers.overlaps && prt2.modifiers.overlaps {
		return
	}

	duplicateRules = append(duplicateRules, [2]*ExpandedRule{rule, other})
}

var redundantRules [][2]*ExpandedRule

func collectRedundantRules(rule, other *ExpandedRule, countRef *int) {
	service := rule.service

	// Count each redundant rule only once.
	if !rule.redundant {
		rule.redundant = true
		*countRef++
		service.redundantCount++
	}

	prt1 := getOrigPrt(rule)
	prt2 := getOrigPrt(other)
	if prt1.modifiers.overlaps && prt2.modifiers.overlaps {
		return
	}

	oservice := other.service
	for _, overlap := range service.Overlaps {
		if oservice == overlap {
			service.overlapsUsed[overlap] = true
			return
		}
	}

	redundantRules = append(redundantRules, [2]*ExpandedRule{rule, other})
}

// Expand path_rules to elementary rules.
func expandRules(rules []*Rule) []*ExpandedRule {
	var result []*ExpandedRule
	for _, rule := range rules {
		service := rule.Service
		for _, src := range rule.Src {
			for _, dst := range rule.Dst {
				for _, prt := range rule.Prt {
					e := fillExpandedRule(rule)
					e.src = src
					e.dst = dst
					e.prt = prt
					result = append(result, e)
					service.ruleCount++
				}
			}
		}
	}
	return result
}

// Build rule tree from nested maps.
// Leaf node has rule as value.
type ruleTree1 map[*proto]*ExpandedRule
type ruleTree2 map[someObj]ruleTree1
type ruleTree3 map[someObj]ruleTree2
type ruleTree4 map[*proto]ruleTree3
type ruleTree5 map[bool]ruleTree4
type ruleTree map[bool]ruleTree5

func (tree ruleTree2) add(dst someObj) ruleTree1 {
	subtree, found := tree[dst]
	if !found {
		subtree = make(ruleTree1)
		tree[dst] = subtree
	}
	return subtree
}
func (tree ruleTree3) add(src someObj) ruleTree2 {
	subtree, found := tree[src]
	if !found {
		subtree = make(ruleTree2)
		tree[src] = subtree
	}
	return subtree
}
func (tree ruleTree4) add(srcRange *proto) ruleTree3 {
	subtree, found := tree[srcRange]
	if !found {
		subtree = make(ruleTree3)
		tree[srcRange] = subtree
	}
	return subtree
}
func (tree ruleTree5) add(deny bool) ruleTree4 {
	subtree, found := tree[deny]
	if !found {
		subtree = make(ruleTree4)
		tree[deny] = subtree
	}
	return subtree
}
func (tree ruleTree) add(stateless bool) ruleTree5 {
	subtree, found := tree[stateless]
	if !found {
		subtree = make(ruleTree5)
		tree[stateless] = subtree
	}
	return subtree
}

// Build rule tree from expanded rules for efficient comparison of rules.
// Rule tree is a nested map for ordering all rules.
// Put attributes with small value set first, to get a more
// memory efficient tree with few branches at root.
func buildRuleTree(rules []*ExpandedRule) (ruleTree, int) {
	var count int
	ruleTree := make(ruleTree)

	// Simpler version of rule tree. It is used for rules without attributes
	// deny, stateless and srcRange.
	simpleTree := make(ruleTree3)

	for _, rule := range rules {
		srcRange := rule.srcRange
		var midTree ruleTree3

		if rule.deny || rule.stateless || srcRange != nil {
			if srcRange == nil {
				srcRange = prtIP
			}
			midTree = ruleTree.add(rule.stateless).add(rule.deny).add(srcRange)
		} else {
			midTree = simpleTree
		}
		leafMap := midTree.add(rule.src).add(rule.dst)

		if otherRule, found := leafMap[rule.prt]; found {
			if rule.log != otherRule.log {
				errMsg("Duplicate rules must have identical log attribute:\n",
					" ", otherRule.printRule(), "\n",
					" ", rule.printRule())
			}

			// Found identical rule.
			//			collectDuplicateRules(rule, otherRule)
			count++
		} else {
			leafMap[rule.prt] = rule
		}
	}

	// Insert simpleTree into ruleTree.
	if len(simpleTree) != 0 {
		ruleTree.add(false).add(false)[prtIP] = simpleTree
	}
	return ruleTree, count
}

func findRedundantRules(cmpHash, chgHash ruleTree) int {
	count := 0
	for stateless, chgHash := range chgHash {
		for {
			if cmpHash, found := cmpHash[stateless]; found {
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
																	for {
																		if cmpRule, found :=
																			cmpHash[prt]; found {
																			if cmpRule !=
																				chgRule &&
																				cmpRule.log ==
																					chgRule.log {
																				collectRedundantRules(chgRule, cmpRule, &count)
																			}
																		}
																		prt = prt.up
																		if prt == nil {
																			break
																		}
																	}
																}
															}
															dst = dst.up()
															if dst == nil {
																break
															}
														}
													}
												}
												src = src.up()
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
			}
			if !stateless {
				break
			}
			stateless = false
		}
	}
	return count
}

func checkExpandedRules(pRules *PathRules) {
	progress("Checking for redundant rules")
	var count int
	dcount := 0
	rcount := 0

	// Process rules in chunks to reduce memory usage.
	// Rules with different src_path / dst_path can't be
	// redundant to each other.
	// Keep deterministic order of rules.
	var index = 0
	path2index := make(map[pathObj]int)
	key2rules := make(map[int][]*Rule)
	add := func(rules []*Rule) {
		for _, rule := range rules {
			key, ok := path2index[rule.SrcPath]
			if !ok {
				key = index
				index++
				path2index[rule.SrcPath] = key
			}
			key2rules[key] = append(key2rules[key], rule)
		}
	}
	add(pRules.Deny)
	add(pRules.Permit)

	for key := 0; key < index; key++ {
		rules := key2rules[key]
		var index = 0
		path2index := make(map[pathObj]int)
		key2rules := make(map[int][]*Rule)
		for _, rule := range rules {
			key, ok := path2index[rule.DstPath]
			if !ok {
				key = index
				index++
				path2index[rule.DstPath] = key
			}
			key2rules[key] = append(key2rules[key], rule)
		}
		for key := 0; key < index; key++ {
			rules := key2rules[key]
			expandedRules := expandRules(rules)
			count += len(expandedRules)
			ruleTree, deleted := buildRuleTree(expandedRules)
			dcount += deleted
			setLocalPrtRelation(rules);
			rcount += findRedundantRules(ruleTree, ruleTree)
		}
	}
	/*
		show_duplicate_rules()
		show_redundant_rules()
		warn_unused_overlaps()
		show_fully_redundant_rules()
		info("Expanded rule count: $count; duplicate: $dcount; redundant: $rcount");
	*/
}

func main() {
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		panic(err)
	}
	var xRules = make(xMap)
	err = sereal.Unmarshal(bytes, &xRules)
	if err != nil {
		panic(err)
	}
	pathRules := convertPathRules(xRules)
	checkExpandedRules(pathRules)
	//	spew.Printf("%+v\n", pathRules)
	//	fmt.Println(rules)
}
