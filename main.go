package main
import (
//	"fmt"
	"io/ioutil"
//	"github.com/davecgh/go-spew/spew"
	"github.com/Sereal/Sereal/Go/sereal"
	"net"
)

var path = "/home/hk/out.sereal"

type xAny interface{}
type xMap = map[string]interface{}
type xArray = []interface{}

type netObj interface{}

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

type Network struct {
	Name string
	IP net.IP
	Mask net.IPMask
	Subnets []*Subnet
	Interfaces []*Interface
	Up netObj
}

func (x *Network)   up () netObj { return x.up }
func (x *Subnet)    up () netObj { return x.up }
func (x *Interface) up () netObj { return x.up }

func convertNetwork (x xAny) *Network {
	m := getMap(x) 
	if n, ok := m["ref"]; ok {
		return n.(*Network)
	}
	n := new(Network)
	m["ref"] = n
	n.Name = m["name"].(string)
	n.IP = m["ip"].([]byte)
	n.Mask = m["mask"].([]byte)
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
	if up, ok := m["up"]; ok {
		n.Up = convertNetObj(up)
	}
	return n
}

type Subnet struct {
	Name string
	IP net.IP
	Network *Network
	Up netObj
}
func convertSubnet (x xAny) *Subnet {
	m := getMap(x) 
	if h, ok := m["ref"]; ok {
		return h.(*Subnet)
	}
	h := new(Subnet)
	m["ref"] = h
	h.Name = m["name"].(string)
	h.IP = m["ip"].([]byte)
	h.Network = convertNetwork(m["network"])
	if up, ok := m["up"]; ok {
		h.Up = convertNetObj(up)
	}
	return h
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
	Name string
	IP net.IP
	Network *Network
	Router *Router
	Up netObj
}
func convertInterface (x xAny) *Interface {
	m := getMap(x) 
	if i, ok := m["ref"]; ok {
		return i.(*Interface)
	}
	i := new(Interface)
	m["ref"] = i
	i.Name = m["name"].(string)
	i.IP = m["ip"].([]byte)
	i.Network = convertNetwork(m["network"])
	if up, ok := m["up"]; ok {
		i.Up = convertNetObj(up)
	}
	return i
}

func convertNetObj (x xAny) netObj {
	m := getMap(x) 
	if o, ok := m["ref"]; ok {
		return o
	}
	if _, ok := m["router"]; ok {
		return convertInterface(x)
	}
	if _, ok := m["network"]; ok {
		return convertSubnet(x)
	}
	return convertNetwork(x)
}

func convertNetObjects (x xAny) []netObj {
	a := getArray(x)
	objects := make([]netObj, len(a))
	for i, x := range a {
		objects[i] = convertNetObj(x)
	}
	return objects
}

type Rule struct {
	Deny bool
	Src []netObj
	Dst []netObj
	//Prt []Prt
	//SrcRange Prt
	// Rule xAny
	Log []string
	//SrcPath pathObj
	//DstPath pathObj
	Stateless bool
	StatelessICMP bool
}
func convertRule (m xMap) *Rule {
	r := new(Rule)
	r.Deny = convertBool(m["deny"])
	r.Src = convertNetObjects(m["src"])
	r.Dst = convertNetObjects(m["dst"])
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
