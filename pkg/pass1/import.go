package pass1

import (
	"fmt"
	"io/ioutil"
	"github.com/Sereal/Sereal/Go/sereal"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

type xAny interface{}
type xMap = map[string]interface{}
type xSlice = []interface{}

func getBool(x xAny) bool {
	switch b := x.(type) {
	case nil:
		return false
	case string:
		return b != "" && b != "0"
	case []byte:
		s := string(b[:])
		return s != "" && s != "0"
	case int:
		return b != 0
	default:
		return true
	}
}

func getInt(x xAny) int {
	switch i := x.(type) {
	case nil:
		return 0
	case string:
		n, err := strconv.Atoi(i)
		if err != nil {
			panic(fmt.Errorf("Can't covert to int: %v", i))
		}
		return n
	case int:
		return i
	default:
		panic(fmt.Errorf("Expected int but got %v", i))
	}
}

func getIP(x xAny) net.IP {
	s := getString(x)
	return net.IP(s)
}

func getString(x xAny) string {
	switch a := x.(type) {
	case nil:
		return ""
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
func getStrings(x xAny) []string {
	if x == nil {
		return nil
	}
	a := getSlice(x)
	result := make([]string, len(a))
	for i, elt := range a {
		result[i] = getString(elt)
	}
	return result
}
func getMapStringString(x xAny) map[string]string {
	m := getMap(x)
	ss := make(map[string]string)
	for k, v := range m {
		ss[k] = getString(v)
	}
	return ss
}

func getSlice(x xAny) xSlice {
	switch a := x.(type) {
	case nil:
		return make(xSlice, 0)
	case xSlice:
		return a
	case *xSlice:
		return *a
	default:
		panic(fmt.Errorf("Expected xSlice or *xSlice but got %v", a))
	}
}

func getMap(x xAny) xMap {
	switch m := x.(type) {
	case nil:
		return make(xMap)
	case xMap:
		return m
	case *xMap:
		return *m
	default:
		panic(fmt.Errorf("Expected xMap or *xMap but got %v", m))
	}
}

func (x *IPObj) setCommon(m xMap) {
	x.Name = getString(m["name"])
	s := getString(m["ip"])
	switch s {
	case "unnumbered":
		x.unnumbered = true
	case "negotiated":
		x.negotiated = true
	case "tunnel":
		x.tunnel = true
	case "bridged":
		x.bridged = true
	default:
		x.IP = net.IP(s)
	}
	if up, ok := m["up"]; ok {
		x.Up = convSomeObj(up)
	}
}
func (x *NetObj) setCommon(m xMap) {
	x.IPObj.setCommon(m)
	x.Network = convNetwork(m["network"])
}

func convNetNat(x xAny) natMap {
	m := getMap(x)
	n := make(map[string]*Network)
	for tag, natNet := range m {
		n[tag] = convNetwork(natNet)
	}
	return n
}

func convIPNat(x xAny) map[string]net.IP {
	m := getMap(x)
	n := make(map[string]net.IP)
	for tag, x := range m {
		n[tag] = getIP(x)
	}
	return n
}

func convNetwork(x xAny) *Network {
	if x == nil {
		return nil
	}
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
		xSubnets := list.(xSlice)
		subnets := make([]*Subnet, len(xSubnets))
		for i, xSubnet := range xSubnets {
			subnets[i] = convSubnet(xSubnet)
		}
		n.Subnets = subnets
	}
	n.Interfaces = convInterfaces(m["interfaces"])
	n.zone = convZone(m["zone"])
	n.hasOtherSubnet = getBool(m["has_other_subnet"])
	n.maxSecondaryNet = convNetwork(m["max_secondary_net"])
	n.nat = convNetNat(m["nat"])
	n.dynamic = getBool(m["dynamic"])
	n.natTag = getString(m["nat_tag"])
	return n
}

func convSubnet(x xAny) *Subnet {
	m := getMap(x)
	if s, ok := m["ref"]; ok {
		return s.(*Subnet)
	}
	s := new(Subnet)
	m["ref"] = s
	s.setCommon(m)
	s.Mask = m["mask"].([]byte)
	s.nat = convIPNat(m["nat"])
	s.id = getString(m["id"])
	return s
}

func convNoNatSet(x xAny) noNatSet {
	if x == nil {
		return nil
	}
	m := getMap(x)
	if n, ok := m[":ref"]; ok {
		return n.(noNatSet)
	}
	n := make(map[string]bool)
	for tag := range m {
		n[tag] = true
	}
	m[":ref"] = noNatSet(&n)
	return &n
}

func convModel(x xAny) *Model {
	m := getMap(x)
	if d, ok := m["ref"]; ok {
		return d.(*Model)
	}
	d := new(Model)
	m["ref"] = d
	d.CommentChar = getString(m["comment_char"])
	d.Class = getString(m["class"])
	d.DoAuth = getBool(m["do_auth"])
	d.canObjectgroup = getBool(m["can_objectgroup"])
	d.logModifiers = getMapStringString(m["log_modifiers"])
	return d
}

func convAclInfo(x xAny) *aclInfo {
	m := getMap(x)
	i := new(aclInfo)
	i.name = getString(m["name"])
	i.noNatSet = convNoNatSet(m["no_nat_set"])
	i.dstNoNatSet = convNoNatSet(m["dst_no_nat_set"])
	i.rules = convRules(m["rules"])
	i.intfRules = convRules(m["intf_rules"])
	i.protectSelf = getBool(m["protect_self"])
	i.addPermit = getBool(m["add_permit"])
	i.addDeny = getBool(m["add_deny"])
	i.filterAnySrc = getBool(m["filter_any_src"])
	i.isCryptoACL = getBool(m["is_crypto_acl"])
	i.isStdACL = getBool(m["is_std_acl"])
	return i
}

func convRouter(x xAny) *Router {
	if x == nil {
		return nil
	}
	m := getMap(x)
	if r, ok := m["ref"]; ok {
		return r.(*Router)
	}
	r := new(Router)
	m["ref"] = r
	r.Name = getString(m["name"])
	r.DeviceName = getString(m["device_name"])
	r.Managed = getString(m["managed"])
	r.AdminIP = getStrings(m["admin_ip"])
	r.Model   = convModel(m["model"])
	r.Log     = getMapStringString(m["log"])
	r.logDeny = getBool(m["log_deny"])
	r.Interfaces = convInterfaces(m["interfaces"])
	r.OrigInterfaces = convInterfaces(m["orig_interfaces"])
	r.crosslinkInterfaces = convInterfaces(m["crosslink_interfaces"])
	if x, ok := m["filter_only"]; ok {
		a := getSlice(x)
		b := make([]net.IPNet, len(a))
		for i, xPair := range a {
			pair := getSlice(xPair)
			ip := getIP(pair[0])
			mask := getIP(pair[1])
			b[i] = net.IPNet{IP: ip, Mask: net.IPMask(mask)}
		}
		r.filterOnly = b
	}
	r.needProtect = getBool(m["need_protect"])
	r.noGroupCode = getBool(m["no_group_code"])
	if x, ok := m["no_secondary_opt"]; ok {
		m := getMap(x)
		n := make(map[*Network]bool)
		for _, x := range m {
			n[convNetwork(x)] = true
		}
		r.noSecondaryOpt = n
	}
	// Hardware
	// OrigHardware
	r.VrfMembers = convRouters(m["vrf_members"])
	r.OrigRouter = convRouter(m["orig_router"])
	r.IPv6 = getBool(m["ipv6"])
	if x, ok := m["acl_list"]; ok {
		a := getSlice(x)
		aclList := make([]*aclInfo, len(a))
		for i, x := range a {
			aclList[i] = convAclInfo(x)
		}
		r.aclList = aclList
	}
	return r
}
func convRouters(x xAny) []*Router {
	if x == nil {
		return nil
	}
	a := getSlice(x)
	routers := make([]*Router, len(a))
	for i, x := range a {
		routers[i] = convRouter(x)
	}
	return routers
}

func convInterface(x xAny) *Interface {
	m := getMap(x)
	if i, ok := m["ref"]; ok {
		return i.(*Interface)
	}
	i := new(Interface)
	m["ref"] = i
	i.setCommon(m)
	i.Router = convRouter(m["router"])
	i.nat = convIPNat(m["nat"])
	return i
}
func convInterfaces(x xAny) []*Interface {
	if x == nil {
		return nil
	}
	a := getSlice(x)
	interfaces := make([]*Interface, len(a))
	for i, x := range a {
		interfaces[i] = convInterface(x)
	}
	return interfaces
}

func convSomeObj(x xAny) someObj {
	m := getMap(x)
	if o, ok := m["ref"]; ok {
		return o.(someObj)
	}
	if _, ok := m["router"]; ok {
		return convInterface(x)
	}
	if _, ok := m["network"]; ok {
		return convSubnet(x)
	}
	return convNetwork(x)
}

func convSomeObjects(x xAny) []someObj {
	a := getSlice(x)
	objects := make([]someObj, len(a))
	for i, x := range a {
		objects[i] = convSomeObj(x)
	}
	return objects
}

func convZone(x xAny) *Zone {
	m := getMap(x)
	if r, ok := m["ref"]; ok {
		return r.(*Zone)
	}
	z := new(Zone)
	m["ref"] = z
	z.Name = getString(m["name"])
	if list, ok := m["networks"]; ok {
		xNetworks := list.(xSlice)
		networks := make([]*Network, len(xNetworks))
		for i, xNetwork := range xNetworks {
			networks[i] = convNetwork(xNetwork)
		}
		z.Networks = networks
	}
	return z
}

func convPathObj(x xAny) pathObj {
	m := getMap(x)
	if o, ok := m["ref"]; ok {
		return o.(pathObj)
	}
	name := getString(m["name"])
	prefix := strings.SplitN(name, ":", 2)[0]
	switch prefix {
	case "interface":
		return convInterface(x)
	case "router":
		return convRouter(x)
//	case "any":
	default:
		return convZone(x)
	}
//	panic(fmt.Errorf("Expected interface|router|zone but got %v", name))
}

func convModifiers(x xAny) modifiers {
	m := getMap(x)
	var n modifiers
	if _, ok := m["reversed"]; ok {
		n.reversed = true
	}
	if _, ok := m["stateless"]; ok {
		n.stateless = true
	}
	if _, ok := m["oneway"]; ok {
		n.oneway = true
	}
	if _, ok := m["src_net"]; ok {
		n.srcNet = true
	}
	if _, ok := m["dst_net"]; ok {
		n.dstNet = true
	}
	if _, ok := m["overlaps"]; ok {
		n.overlaps = true
	}
	if _, ok := m["no_check_supernet_rules"]; ok {
		n.noCheckSupernetRules = true
	}
	return n
}

func convProto(x xAny) *proto {
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
	if t, ok := m["type"]; ok {
		p.icmpType = t.(int)
	} else {
		p.icmpType = -1
	}
	if c, ok := m["code"]; ok {
		p.icmpCode = c.(int)
	} else {
		p.icmpCode = -1
	}
	if m, ok := m["modifiers"]; ok {
		p.modifiers = convModifiers(m)
	}
	if list, ok := m["range"]; ok {
		a := getSlice(list)
		p.ports = [2]int{a[0].(int), a[1].(int)}
	}
	if _, ok := m["established"]; ok {
		p.established = true
	}
	if u, ok := m["up"]; ok {
		p.up = convProto(u)
	}
	p.src = convProto(m["src_range"])
	p.dst = convProto(m["dst_range"])
	p.main = convProto(m["main"])
	return p
}
func convProtos(x xAny) []*proto {
	a := getSlice(x)
	list := make([]*proto, len(a))
	for i, x := range a {
		list[i] = convProto(x)
	}
	return list
}
func convProtoMap(x xAny) map[string]*proto {
	m := getMap(x)
	n := make(map[string]*proto)
	for name, xProto := range m {
		n[name] = convProto(xProto)
	}
	return n
}

func convProtoOrName (x xAny) protoOrName {
	switch u := x.(type) {
	case xSlice, *xSlice:
		return getStrings(x)
	case xMap, *xMap:
		return convProto(x)
	default:
		panic(fmt.Errorf("Expected (*)xSlice or xMap but got %v", u))
	}
	return nil
}
func convProtoOrNames (x xAny) []protoOrName {
	a := getSlice(x)
	list := make([]protoOrName, len(a))
	for i, x := range a {
		list[i] = convProtoOrName(x)
	}
	return list
}

func convService(x xAny) *Service {
	m := getMap(x)
	if s, ok := m["ref"]; ok {
		return s.(*Service)
	}
	s := new(Service)
	m["ref"] = s
	s.name = getString(m["name"])
	s.disabled = getBool(m["disabled"])
	if list, ok := m["overlaps"]; ok {
		xOverlaps := list.(xSlice)
		overlaps := make([]*Service, len(xOverlaps))
		for i, xOverlap := range xOverlaps {
			overlaps[i] = convService(xOverlap)
		}
		s.Overlaps = overlaps
		s.overlapsUsed = make(map[*Service]bool)
	}
	return s
}
func convServiceMap(x xAny) map[string]*Service {
	m := getMap(x)
	n := make(map[string]*Service)
	for name, xService := range m {
		n[name] = convService(xService)
	}
	return n
}

func convUnexpRule(x xAny) *UnexpRule {
	m := getMap(x)
	if r, ok := m["ref"]; ok {
		return r.(*UnexpRule)
	}
	r := new(UnexpRule)
	m["ref"] = r
	r.Service = convService(m["service"])
	r.Prt = convProtoOrNames(m["prt"])
	return r
}

func convRule(m xMap) *Rule {
	r := new(Rule)
	r.Deny = getBool(m["deny"])
	r.Src = convSomeObjects(m["src"])
	r.Dst = convSomeObjects(m["dst"])
	r.Prt = convProtos(m["prt"])
	r.SrcRange = convProto(m["src_range"])
	r.SrcPath = convPathObj(m["src_path"])
	r.DstPath = convPathObj(m["dst_path"])
	if log, ok := m["log"]; ok {
		r.Log = getString(log)
	}
	r.Stateless = getBool(m["stateless"])
	r.StatelessICMP = getBool(m["stateless_icmp"])
	r.Overlaps = getBool(m["overlaps"])
	r.Rule = convUnexpRule(m["rule"])
	r.someNonSecondary = getBool(m["some_non_secondary"])
	r.somePrimary = getBool(m["some_primary"])
	return r
}

func convRules(x xAny) []*Rule {
	if x == nil {
		return nil
	}
	a := getSlice(x)
	rules := make([]*Rule, len(a))
	for i, x := range a {
		rules[i] = convRule(getMap(x))
	}
	return rules
}

func convPathRules(x xAny) *PathRules {
	m := getMap(x)
	rules := new(PathRules)
	if v := m["permit"]; v != nil {
		rules.Permit = convRules(v)
	}
	if v := m["deny"]; v != nil {
		rules.Deny = convRules(v)
	}
	return rules
}

func convConfig(x xAny) Config {
	m := getMap(x)
	c := Config{
		Verbose: getBool(m["verbose"]),
		TimeStamps: getBool(m["time_stamps"]),
		Pipe: getBool(m["pipe"]),
		MaxErrors:  getInt(m["max_errors"]),
		CheckDuplicateRules: getString(m["check_duplicate_rules"]),
		CheckRedundantRules: getString(m["check_redundant_rules"]),
		CheckFullyRedundantRules: getString(m["check_fully_redundant_rules"]),
	}
	return c
}

func ImportFromPerl () {
	var bytes []byte
	var err error
	if len(os.Args) > 1 {
		name := os.Args[1]
		bytes, err = ioutil.ReadFile(name)
	} else {
		bytes, err = ioutil.ReadAll(os.Stdin)
	}
	if err != nil {
		panic(err)
	}
	var m xMap
	err = sereal.Unmarshal(bytes, &m)
	if err != nil {
		panic(err)
	}
	config = convConfig(m["config"])
	startTime = time.Unix(int64(m["start_time"].(int)), 0)
	prtIP = convProto(m["prt_ip"])
	protocols = convProtoMap(m["protocols"])
	services = convServiceMap(m["services"])
	pathRules = convPathRules(m["path_rules"])
	managedRouters = convRouters(m["managed_routers"])
	routingOnlyRouters = convRouters(m["routing_only_routers"])
	outDir = getString(m["out_dir"])
}
