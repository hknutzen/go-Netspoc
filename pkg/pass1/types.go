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
	autoDefaultRoute      bool
}

type someObj interface {
	name() string
	network() *Network
	up() someObj
	address(nn natSet) net.IPNet
	getAttr(attr string) string
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
	hidden     bool
	natTag     string
	certId     string
	radiusAttributes map[string]string
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
	ldapId  string
	radiusAttributes map[string]string
}

type Model struct {
	CommentChar string
	Class       string
	crypto      string
	DoAuth      bool
	canObjectgroup bool
	cryptoInContext bool
	filter      string
	logModifiers map[string]string
	needAcl     bool
	noCryptoFilter bool
	printInterface bool
	routing     string
	stateless   bool
	usePrefix   bool
}

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
	model      *Model
	Log        map[string]string
	logDeny    bool
	Interfaces []*Interface
	origInterfaces []*Interface
	crosslinkInterfaces []*Interface
	filterOnly []net.IPNet
	needProtect bool
	noGroupCode bool
	noSecondaryOpt map[*Network]bool
	Hardware   []*Hardware
	OrigHardware []*Hardware
	origRouter *Router
	radiusAttributes map[string]string
	routingOnly bool
	trustPoint string
	VrfMembers []*Router
	IPv6       bool
	aclList    []*aclInfo
	vrf        string
}

type Interface struct {
	NetObj
	Router  		  *Router
	crypto        *Crypto
	hub           []*Crypto
	spoke         *Crypto
	id            string
	isHub         bool
	hardware      *Hardware
	mainInterface *Interface
	nat     		  map[string]net.IP
	natSet        natSet
	peer    		  *Interface
	peerNetworks  []*Network
	realInterface *Interface
	redundancyInterfaces []*Interface
	redundant     bool
	routes        map[*Interface]map[*Network]bool
	routing       *Routing
	rules         []*Rule
	intfRules     []*Rule
	outRules      []*Rule
	idRules       map[string]*idInterface
	short         bool
	zone          *Zone
}
type idInterface struct {
	*Interface
	src *Subnet
}

type Routing struct {
	name   string
	prt    *proto
	mcast  []net.IP
	mcast6 []net.IP
}

type Hardware struct {
	interfaces  []*Interface
	loopback    bool
	name        string
	natSet      natSet
	dstNatSet   natSet
	needOutAcl  bool
	noInAcl     bool
	rules       []*Rule
	intfRules   []*Rule
	outRules    []*Rule
	ioRules     map[string][]*Rule
	subcmd      []string
}

type Crypto struct {
	ipsec *Ipsec
	detailedCryptoAcl bool
}
type Ipsec struct {
	name     	  		string
	isakmp   	  		*Isakmp
	lifetime 	  		*[2]int
	ah       	  		string
	espAuthentication string
	espEncryption 		string
	pfsGroup      		string
}
type Isakmp struct {
	name           string
	authentication string
	encryption     string
	group          string
	hash           string
	trustPoint     string
	ikeVersion     int
	lifetime       int
}

type Zone struct {
	Name     string
	Networks []*Network
	Attr     map[string]string
	InArea   *Area
	interfaces []*Interface
	zoneCluster []*Zone
}

type Area struct {
	Name     string
	Attr     map[string]string
	InArea   *Area
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
	name             	 string
	disabled         	 bool
	ruleCount        	 int
	duplicateCount   	 int
	redundantCount   	 int
	hasSameDupl      	 map[*Service]bool
	Overlaps         	 []*Service
	overlapsUsed     	 map[*Service]bool
	overlapsRestricted bool
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
