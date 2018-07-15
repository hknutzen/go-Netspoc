package main
import (
	"fmt"
	"io/ioutil"
//	"github.com/davecgh/go-spew/spew"
	"github.com/Sereal/Sereal/Go/sereal"
	"net"
)

var path = "/home/hk/out.sereal"

type xAny interface{}
type xMap = map[string]interface{}
type xArray = []interface{}

type someObj interface{
	up () someObj
	setCommon (m xMap)
}
type pathObj interface {}

func convertBool (x xAny) bool {
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

func convertStrings(x xAny) []string {
	a := getArray(x)
	result := make([]string, len(a))
	for i, elt := range a {
		result[i] = elt.(string)
	}
	return result
}

func getArray (x xAny) xArray {
	switch a := x.(type) {
	case xArray:
		return a
	case *xArray:
		return *a 
	default:
		panic("Expected xArray or *xArray")
	}
}

func getMap (x xAny) xMap {
	switch m := x.(type) {
	case xMap:
		return m
	case *xMap:
		return *m
	default:
		panic("Expected xMap or *xMap")
	}
}

type IPObj struct {
	Name string
	IP net.IP
	Up someObj
}

func (x *IPObj) up () someObj { return x.Up }
func (x *IPObj) setCommon (m xMap) {
	x.Name = m["name"].(string)
	ip := m["ip"]
	if ip == nil {
		fmt.Println(x.Name)
	} else {
		x.IP = m["ip"].([]byte)
	}
	if up, ok := m["up"]; ok {
		x.Up = convertNetObj(up)
	}
}

type Network struct {
	IPObj
	Mask net.IPMask
	Subnets []*Subnet
	Interfaces []*Interface
}

func convertNetwork (x xAny) *Network {
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

type Subnet struct {
	IPObj
	Mask net.IPMask
	Network *Network
}
func convertSubnet (x xAny) *Subnet {
	m := getMap(x) 
	if s, ok := m["ref"]; ok {
		return s.(*Subnet)
	}
	s := new(Subnet)
	m["ref"] = s
	s.setCommon(m)
	s.Mask = m["mask"].([]byte)
	s.Network = convertNetwork(m["network"])
	return s
}
type Router struct {
	Name string
	Managed string
	Interfaces []*Interface
}
func convertRouter (x xAny) *Router {
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
	IPObj
	Network *Network
	Router *Router
}
func convertInterface (x xAny) *Interface {
	m := getMap(x) 
	if i, ok := m["ref"]; ok {
		return i.(*Interface)
	}
	i := new(Interface)
	m["ref"] = i
	i.setCommon(m)
	i.Network = convertNetwork(m["network"])
	return i
}

func convertNetObj (x xAny) someObj {
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

func convertNetObjects (x xAny) []someObj {
	a := getArray(x)
	objects := make([]someObj, len(a))
	for i, x := range a {
		objects[i] = convertNetObj(x)
	}
	return objects
}

type Zone struct {
	Name string
	Networks []*Network
}
func convertZone (x xAny) *Zone {
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

func convertPathObj (x xAny) pathObj {
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

type Rule struct {
	Deny bool
	Src []someObj
	Dst []someObj
	//Prt []Prt
	//SrcRange Prt
	// Rule xAny
	Log []string
	SrcPath pathObj
	DstPath pathObj
	Stateless bool
	StatelessICMP bool
}
func convertRule (m xMap) *Rule {
	r := new(Rule)
	r.Deny = convertBool(m["deny"])
	r.Src = convertNetObjects(m["src"])
	r.Dst = convertNetObjects(m["dst"])
	r.SrcPath = convertPathObj(m["src_path"])
	r.DstPath = convertPathObj(m["dst_path"])
	if list, ok := m["log"]; ok {
		r.Log = convertStrings(list)
	}
	r.Stateless = convertBool(m["stateless"])
	r.StatelessICMP = convertBool(m["stateless_icmp"])
	return r
}

func convertRules (a xArray) []*Rule {
	rules := make([]*Rule, len(a))
	for i, x := range a {
		rules[i] = convertRule(x.(xMap))
	}
	return rules
}

type PathRules struct {
	Permit []*Rule
	Deny []*Rule
}
func convertPathRules (m xMap) *PathRules {
	rules := new(PathRules)
	if v := m["permit"]; v != nil {
		rules.Permit = convertRules(v.(xArray))
	}
	if v := m["deny"]; v != nil {
		rules.Deny = convertRules(v.(xArray))
	}
	return rules
}

func check_expanded_rules (pRules PathRules) {
	//var count int

	// Process rules in chunks to reduce memory usage.
	// Rules with different src_path / dst_path can't be
   // redundant to each other.
   // Keep deterministic order of rules.
	var index = 0
	path2index := make(map[pathObj]int)
	key2rules := make(map[int][]*Rule)
	add := func (rules []*Rule) {
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
			_ = key2rules[key]
			//rules := key2rules[key]
			//expandedRules := expandRules(rules)
			//count += len(expandedRules)
			//ruleTree, deleted := buildRuleTree(expanded_rules)
			//dcount += deleted
			//setLocalPrtRelation(rules);
			//rcount += findRedundantRules(rule_tree, rule_tree);
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
	_ = pathRules
//	spew.Printf("%+v\n", pathRules)
//	fmt.Println(rules)
}
