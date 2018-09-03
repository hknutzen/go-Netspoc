package main

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"
)

type someObj interface {
	name() string
	network() *Network
	up() someObj
	setCommon(m xMap) // for importFromPerl
}
type pathObj interface{}

type IPObj struct {
	Name string
	IP   net.IP
	Up   someObj
}

func (x *IPObj) name() string { return x.Name }
func (x *IPObj) up() someObj { return x.Up }

type Network struct {
	IPObj
	Mask       net.IPMask
	Subnets    []*Subnet
	Interfaces []*Interface
	zone       *Zone
}

func (x *Network) network() *Network { return x }

type NetObj struct {
	IPObj
	Network *Network
}
func (x *NetObj) network() *Network { return x.Network }

type Subnet struct {
	NetObj
	Mask    net.IPMask
}

type Router struct {
	Name       string
	Managed    string
	Interfaces []*Interface
}

type Interface struct {
	NetObj
	Router  *Router
}

type Zone struct {
	Name     string
	Networks []*Network
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
	icmpType    int
	icmpCode    int
	modifiers   modifiers
	src *proto
	dst *proto
	main *proto
	ports       [2]int
	established bool
	up          *proto
	localUp     *proto
	hasNeighbor bool
	isUsed bool
}

var prtIP = &proto{name: "ip", proto: "ip"}

type Service struct {
	name             string
	disabled         bool
	ruleCount        int
	duplicateCount   int
	redundantCount   int
	hasSameDupl      map[*Service]bool
	Overlaps         []*Service
	overlapsUsed     map[*Service]bool
}

type UnexpRule struct {
	Prt           []protoOrName
	Service       *Service
}
	
type Rule struct {
	Deny          bool
	Src           []someObj
	Dst           []someObj
	Prt           []*proto
	SrcRange      *proto
	Log           string
	Rule          *UnexpRule
	SrcPath       pathObj
	DstPath       pathObj
	Stateless     bool
	StatelessICMP bool
	Overlaps      bool
}

type PathRules struct {
	Permit []*Rule
	Deny   []*Rule
}

type Config struct {
	CheckDuplicateRules          string
	CheckRedundantRules          string
	CheckFullyRedundantRules     string
	Verbose                      bool
	TimeStamps                   bool
	MaxErrors                    int
}

var config Config

var startTime time.Time
var errorCounter int

func info(format string, args ...interface{}) {
	if config.Verbose {
		string := fmt.Sprintf(format, args...)
		fmt.Fprintln(os.Stderr, string)
	}
}

func checkAbort() {
	errorCounter++
	if errorCounter >= config.MaxErrors {
		fmt.Fprintf(os.Stderr, "Aborted after %d errors\n", errorCounter)
		os.Exit(errorCounter)
	}
}

func errMsg(format string, args ...interface{}) {
	string := "Error: " + fmt.Sprintf(format, args...)
	fmt.Fprintln(os.Stderr, string)
	checkAbort()
}

func warnMsg(format string, args ...interface{}) {
	string := "Warning: " + fmt.Sprintf(format, args...)
	fmt.Fprintln(os.Stderr, string)
}

func warnOrErrMsg (errType, format string, args ...interface{}) {
	if errType == "warn" {
        warnMsg(format, args...)
    } else {
        errMsg(format, args...)
    }
}

func progress(msg string) {
	if config.Verbose {
		if config.TimeStamps {
			msg = fmt.Sprintf("%.0fs %s", time.Since(startTime).Seconds(), msg)
		}
		info(msg)
	}
}

type protoOrName interface{}
type ProtoList []*proto

func (l *ProtoList)push(p *proto) {
	*l = append(*l, p)
}

var protocols map[string]*proto

type ProtoGroup struct {
	pairs []protoOrName
	elements []*proto
	recursive bool
	isUsed bool
}
var protocolgroups map[string]*ProtoGroup

func expandProtocols(list []protoOrName, context string) []*proto {
	result := make(ProtoList, 0)
	for _, pair := range list {
		switch p := pair.(type) {
			
		// Handle anonymous protocol.
		case *proto:
			result.push(p)

		case []string:
			typ, name := p[0], p[1]
			switch typ {
			case "protocol":
            if prt, ok := protocols[name]; ok {
					result.push(prt)

					// Currently needed by external program 'cut-netspoc'.
					prt.isUsed = true
            } else {
					errMsg("Can't resolve reference to %s:%s in %s",
						typ, name, context)
            }
			case "protocolgroup":
            if prtgroup, ok := protocolgroups[name]; ok {
					if prtgroup.recursive {
						errMsg("Found recursion in definition of %s", context)
						prtgroup.elements = nil

					// Check if it has already been converted
               // from names to references.
					} else if !prtgroup.isUsed {
						prtgroup.isUsed = true

						// Detect recursive definitions.
						prtgroup.recursive = true
						prtgroup.elements =
							expandProtocols(prtgroup.pairs, typ+":"+name)
						prtgroup.recursive = false
					}
					for _, prt := range prtgroup.elements {
						result.push(prt)
					}
            } else {
					errMsg("Can't resolve reference to %s:%s in %s",
						typ, name, context)
            }
			default:
            errMsg("Unknown type of  %s:%s in %s",
					typ, name, context)
			}
		}
	}
	return result
}

type ExpandedRule struct {
	deny      bool
	stateless bool
	src       someObj
	dst       someObj
	srcRange  *proto
	prt       *proto
	log       string
	rule      *UnexpRule
	redundant bool
	overlaps  bool
}

func fillExpandedRule(rule *Rule) *ExpandedRule {
	return &ExpandedRule{
		deny:      rule.Deny,
		stateless: rule.Stateless,
		log:       rule.Log,
		srcRange:  rule.SrcRange,
		rule:      rule.Rule,
		overlaps:  rule.Overlaps,
	}
}

func (r *Rule) print() {
	e := fillExpandedRule(r)
	e.src = r.Src[0]
	e.dst = r.Dst[0]
	e.prt = r.Prt[0]
	e.print()
}

func (r *ExpandedRule) print() string {
	extra := ""
	if r.log != "" {
		extra += " log=" + r.log + ";"
	}
	if r.stateless {
		extra += " stateless"
	}
	if r.rule.Service != nil {
		extra += " of " + r.rule.Service.name
	}
	var action string
	if r.deny {
		action = "deny"
	} else {
		action = "permit"
	}
	origPrt := getOrigPrt(r)
	return fmt.Sprintf("%s src=%s; dst=%s; prt=%s;%s",
		action, r.src.name(), r.dst.name(), origPrt.name, extra)
}

func isSubRange(p *proto, o *proto) bool {
	l1, h1 := p.ports[0], p.ports[1]
	l2, h2 := o.ports[0], o.ports[1]
	return l2 <= l1 && h1 <= h2
}

func getOrigPrt(rule *ExpandedRule) *proto {
	prt := rule.prt
	proto := prt.proto
	oRule := rule.rule
	service := oRule.Service
	list := expandProtocols(oRule.Prt, service.name)
	for _, oPrt := range list {
		if proto != oPrt.proto {
			continue
		}
		switch oPrt.proto {
		case "tcp", "udp":
			if !isSubRange(prt, oPrt.dst) {
				continue
			}
			srcRange := rule.srcRange
			if (srcRange == nil) != (oPrt.src == nil) {
				continue
			} else if srcRange == nil {
				return oPrt
			} else if isSubRange(srcRange, oPrt.src) {
				return oPrt
			}
		default:
			if mainPrt := oPrt.main; main != nil {
				if mainPrt == prt {
					return oPrt
				}
			}
		}
	}
	return prt
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

func collectDuplicateRules(rule, other *ExpandedRule) {
	service := rule.rule.Service

	// Mark duplicate rules in both services.

	// But count each rule only once. For duplicate rules, this can
	// only occur for rule other, because all identical rules are
	// compared with other. But we need to mark rule as well, because
	// it must only be counted once, if it is both duplicate and
	// redundandant.
	rule.redundant = true
	service.duplicateCount++
	oservice := other.rule.Service
	if !other.redundant {
		oservice.duplicateCount++
	}
	other.redundant = true

	// Link both services, so we later show only one of both service as
	// redundant.
	if service.hasSameDupl == nil {
		service.hasSameDupl = make(map[*Service]bool)
	}
	service.hasSameDupl[oservice] = true
	if oservice.hasSameDupl == nil {
		oservice.hasSameDupl = make(map[*Service]bool)
	}
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
	if rule.overlaps && other.overlaps {
		return
	}
	if config.CheckDuplicateRules == "0" {
		return
	}

	duplicateRules = append(duplicateRules, [2]*ExpandedRule{rule, other})
}

type twoNames [2]string
type namePairs []twoNames

func (s namePairs)sort() {
	sort.Slice(s, func(i, j int) bool {
		switch strings.Compare(s[i][0], s[j][0]) {
		case -1:
			return true
		case 1:
			return false
		}
		return strings.Compare(s[i][1], s[j][1]) == -1
	})
}

func showDuplicateRules () {
	if duplicateRules == nil {
		return
	}
	sNames2Duplicate := make(map[twoNames][]*ExpandedRule)
	for _, pair := range duplicateRules {
		rule, other := pair[0], pair[1]
		key := twoNames{rule.rule.Service.name, other.rule.Service.name}
		sNames2Duplicate[key] = append(sNames2Duplicate[key], rule)
	}
	duplicateRules = nil

	namePairs := make(namePairs, 0, len(sNames2Duplicate))
	for pair := range sNames2Duplicate {
		namePairs = append(namePairs, pair)
	}
	namePairs.sort()
	for _, pair := range namePairs {
		sName, oName := pair[0], pair[1]
		rules := sNames2Duplicate[pair]
		msg := "Duplicate rules in " + sName + " and " + oName + ":";
		for _, rule := range rules {
			msg += "\n  " + rule.print()
		}
		warnOrErrMsg(config.CheckDuplicateRules, msg)
	}
}

var redundantRules [][2]*ExpandedRule

func collectRedundantRules(rule, other *ExpandedRule, countRef *int) {
	service := rule.rule.Service

	// Count each redundant rule only once.
	if !rule.redundant {
		rule.redundant = true
		*countRef++
		service.redundantCount++
	}

	if rule.overlaps && other.overlaps {
		return
	}

	oservice := other.rule.Service
	for _, overlap := range service.Overlaps {
		if oservice == overlap {
			service.overlapsUsed[overlap] = true
			return
		}
	}

	redundantRules = append(redundantRules, [2]*ExpandedRule{rule, other})
}

func showRedundantRules() {
	if redundantRules == nil {
		return
	}

	sNames2Redundant := make(map[twoNames][][2]*ExpandedRule)
	for _, pair := range redundantRules {
		rule, other := pair[0], pair[1]
		key := twoNames{rule.rule.Service.name, other.rule.Service.name}
		sNames2Redundant[key] = append(sNames2Redundant[key], pair)
	}
	redundantRules = nil

	action := config.CheckRedundantRules
	if action == "0" {
		return
	}
	namePairs := make(namePairs, 0, len(sNames2Redundant))
	for pair := range sNames2Redundant {
		namePairs = append(namePairs, pair)
	}
	namePairs.sort()
	for _, pair := range namePairs {
		sName, oName := pair[0], pair[1]
		rulePairs := sNames2Redundant[pair]
		msg := "Redundant rules in " + sName + " compared to " + oName + ":\n  ";
		var list []string
		for _, pair := range rulePairs {
			list = append(list, pair[0].print() + "\n< " + pair[1].print())
		}
		sort.Strings(list)
		msg += strings.Join(list, "\n  ")
		warnOrErrMsg(action, msg)
	}
}

var services map[string]*Service

func showFullyRedundantRules() {
	action := config.CheckFullyRedundantRules
	if action == "0" {
		return
	}
	sNames := make([]string, 0, len(services))
	for name := range services {
		sNames = append(sNames, name)
	}
	sort.Strings(sNames)
	keep := make(map[*Service]bool)
	for _, name := range sNames {
		service := services[name]
		if keep[service] {
			continue
		}
		ruleCount := service.ruleCount
		if ruleCount == 0 {
			continue
		}
		if service.duplicateCount + service.redundantCount != ruleCount {
			continue
		}
		for service := range service.hasSameDupl {
			keep[service] = true
		}
		warnOrErrMsg(action, service.name + " is fully redundant")
	}
}

func warnUnusedOverlaps() {
	var errList []string
	for _, service := range services {
		if service.disabled {
			continue
		}
		if overlaps := service.Overlaps; overlaps != nil {
			used := service.overlapsUsed
			for _, overlap := range overlaps {
				if overlap.disabled || used[overlap] {
					continue
				}
				errList = append(errList,
					fmt.Sprintf("Useless 'overlaps = %s'  in %s",
						overlap.name, service.name))
			}
		}
	}
	sort.Strings(errList)
	for _, msg := range errList {
		warnMsg(msg)
	}
}

// Expand path_rules to elementary rules.
func expandRules(rules []*Rule) []*ExpandedRule {
	var result []*ExpandedRule
	for _, rule := range rules {
		service := rule.Rule.Service
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
				errMsg(
					"Duplicate rules must have identical log attribute:\n %s\n %s",
					otherRule.print(), rule.print())
			}

			// Found identical rule.
			collectDuplicateRules(rule, otherRule)
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
																		prt = prt.localUp
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

var pathRules *PathRules

func checkExpandedRules() {
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
	add(pathRules.Deny)
	add(pathRules.Permit)

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
	showDuplicateRules()
	showRedundantRules()
	warnUnusedOverlaps()
	showFullyRedundantRules()
	info("Expanded rule count: %d; duplicate: %d; redundant: %d",
		count, dcount, rcount)
}

func main() {
	startTime = time.Now()
	importFromPerl()
	checkExpandedRules()
	os.Exit(errorCounter)
}
