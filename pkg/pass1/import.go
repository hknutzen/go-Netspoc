package pass1

import (
	"fmt"
	"io/ioutil"
	"github.com/Sereal/Sereal/Go/sereal"
	"net"
	"os"
	"strconv"
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
	case int:
		return b != 0
	default:
		return true
	}
}

func getInt(x xAny) int {
	switch i := x.(type) {
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
	a := getSlice(x)
	result := make([]string, len(a))
	for i, elt := range a {
		result[i] = getString(elt)
	}
	return result
}

func getSlice(x xAny) xSlice {
	switch a := x.(type) {
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
	case xMap:
		return m
	case *xMap:
		return *m
	default:
		panic(fmt.Errorf("Expected xMap or *xMap but got %v", m))
	}
}

func (x *IPObj) setCommon(m xMap) {
	x.Name = m["name"].(string)
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

func convNetwork(x xAny) *Network {
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
	if list, ok := m["interfaces"]; ok {
		xInterfaces := list.(xSlice)
		interfaces := make([]*Interface, len(xInterfaces))
		for i, xInterface := range xInterfaces {
			interfaces[i] = convInterface(xInterface)
		}
		n.Interfaces = interfaces
	}
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
	return s
}

func convNoNatSet(x xAny) noNatSet {
	m := getMap(x)
	if n, ok := m[":ref"]; ok {
		return n.(noNatSet)
	}
	n := make(map[string]bool)
	m[":ref"] = &n
	for tag := range m {
		n[tag] = true
	}
	return &n
}

func convAclInfo(x xAny) *aclInfo {
	m := getMap(x)
	i := new(aclInfo)
	i.name = getString(m["name"])
	i.noNatSet = convNoNatSet(m["no_nat_set"])
	i.dstNoNatSet = convNoNatSet(m["dstNoNatSet"])
	i.rules = convRules(m["rules"])
	i.intfRules = convRules(m["intf_rules"])
	i.protectSelf = getBool(m["protect_self"])
	i.addPermit = getBool(m["add_permit"])
	i.addDeny = getBool(m["add_deny"])
	i.filterAnySrc = getBool(m["filter_any_src"])
	i.isCryptoAcl = getBool(m["is_crypto_acl"])
	return i
}

func convRouter(x xAny) *Router {
	m := getMap(x)
	if r, ok := m["ref"]; ok {
		return r.(*Router)
	}
	r := new(Router)
	m["ref"] = r
	r.Name = getString(m["name"])
	r.DeviceName = getString(m["device_name"])
	r.Managed = getString(m["managed"])
	r.AdminIP = getString(m["admin_ip"])
	r.Interfaces = convInterfaces(m["interfaces"])
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

func convInterface(x xAny) *Interface {
	m := getMap(x)
	if i, ok := m["ref"]; ok {
		return i.(*Interface)
	}
	i := new(Interface)
	m["ref"] = i
	i.setCommon(m)
	i.Router = convRouter(m["router"])
	return i
}
func convInterfaces(x xAny) []*Interface {
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
	z.Name = m["name"].(string)
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
	if _, ok := m["router"]; ok {
		return convInterface(x)
	}
	if _, ok := m["managed"]; ok {
		return convRouter(x)
	}
	return convZone(x)
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
	if t, ok := m["icmp_type"]; ok {
		p.icmpType = t.(int)
	}
	if c, ok := m["icmp_code"]; ok {
		p.icmpCode = c.(int)
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
	s.name = m["name"].(string)
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
	return r
}

func convRules(x xAny) []*Rule {
	a := getSlice(x)
	rules := make([]*Rule, len(a))
	for i, x := range a {
		rules[i] = convRule(x.(xMap))
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
	prtIP = convProto(m["prt_ip"])
	protocols = convProtoMap(m["protocols"])
	services = convServiceMap(m["services"])
	pathRules = convPathRules(m["path_rules"])
}
