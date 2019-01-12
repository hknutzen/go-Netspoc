package pass1

import (
	"net"
)

type Config struct {
	CheckDuplicateRules          string
	CheckRedundantRules          string
	CheckFullyRedundantRules     string
	Verbose                      bool
	TimeStamps                   bool
	Pipe                         bool
	MaxErrors                    int
}

type someObj interface {
	name() string
	network() *Network
	up() someObj
	address(nn natSet) net.IPNet
	setCommon(m xMap) // for importFromPerl
}
type pathObj interface{}

type IPObj struct {
	Name string
	IP   net.IP
	unnumbered bool
	negotiated bool
	tunnel bool
	bridged bool
	Up   someObj
}

func (x *IPObj) name() string { return x.Name }
func (x *IPObj) up() someObj { return x.Up }

type natMap map[string]*Network

type Network struct {
	IPObj
	Mask       net.IPMask
	Subnets    []*Subnet
	Interfaces []*Interface
	zone       *Zone
	hasOtherSubnet bool
	maxSecondaryNet *Network
	nat        map[string]*Network
	dynamic    bool
	natTag     string
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
	nat     map[string]net.IP
	id      string
}

type Model struct {
	CommentChar string
	Class       string
	DoAuth      bool
	canObjectgroup bool
	logModifiers map[string]string
}
type Hardware struct {}

// Use pointer to map, because we need to test natSet for equality,
// so we can use it as map key.
type natSet *map[string]bool

type aclInfo struct {
	name string
	natSet natSet
	dstNatSet natSet
	rules []*Rule
	intfRules []*Rule
	protectSelf bool
	addPermit bool
	addDeny bool
	filterAnySrc bool
	isStdACL bool
	isCryptoACL bool
	needProtect []net.IPNet
	subAclList []*aclInfo
}

type Router struct {
	Name       string
	DeviceName string
	Managed    string
	AdminIP    []string
	Model      *Model
	Log        map[string]string
	logDeny    bool
	Interfaces []*Interface
	OrigInterfaces []*Interface
	crosslinkInterfaces []*Interface
	filterOnly []net.IPNet
	needProtect bool
	noGroupCode bool
	noSecondaryOpt map[*Network]bool
	Hardware   []*Hardware
	OrigHardware []*Hardware
	VrfMembers []*Router
	OrigRouter *Router
	IPv6       bool
	aclList    []*aclInfo
}

type Interface struct {
	NetObj
	Router  *Router
	nat     map[string]net.IP
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
	printed string
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
	someNonSecondary bool
	somePrimary   bool
}

type PathRules struct {
	Permit []*Rule
	Deny   []*Rule
}

type protoOrName interface{}
type ProtoList []*proto

type ProtoGroup struct {
	pairs []protoOrName
	elements []*proto
	recursive bool
	isUsed bool
}
