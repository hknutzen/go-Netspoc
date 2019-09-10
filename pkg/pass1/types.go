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
	getName() string
	getNetwork() *Network
	getUp() someObj
	address(nn natSet) net.IPNet
	getAttr(attr string) string
	setCommon(m xMap) // for importFromPerl
}

type ipObj struct {
	name string
	ip   net.IP
	unnumbered bool
	negotiated bool
	short bool
	tunnel bool
	bridged bool
	up   someObj
}

func (x *ipObj) getName() string { return x.name }
func (x *ipObj) getUp() someObj { return x.up }

type natMap map[string]*Network

type Network struct {
	ipObj
	attr       map[string]string
	mask       net.IPMask
	subnets    []*Subnet
	interfaces []*Interface
	zone       *Zone
	hasOtherSubnet bool
	maxSecondaryNet *Network
	nat        map[string]*Network
	dynamic    bool
	hidden     bool
	ipV6       bool
	natTag     string
	certId     string
	filterAt   map[int]bool
	hasIdHosts bool
	radiusAttributes map[string]string
}

func (x *Network) getNetwork() *Network { return x }

type netObj struct {
	ipObj
	network *Network
}
func (x *netObj) getNetwork() *Network { return x.network }

type Subnet struct {
	netObj
	mask    net.IPMask
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
	hasIoAcl    bool
	noCryptoFilter bool
	printInterface bool
	routing     string
	stateless   bool
	statelessSelf bool
	statelessICMP bool
	usePrefix   bool
}

// Use pointer to map, because we need to test natSet for equality,
// so we can use it as map key.
type natSet *map[string]bool

type aclInfo struct {
	name string
	natSet natSet
	dstNatSet natSet
	rules RuleList
	intfRules RuleList
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
	pathStoreData
	pathObjData
	name       string
	deviceName string
	managed    string
	semiManaged bool
	adminIP    []string
	model      *Model
	log        map[string]string
	logDeny    bool
	localMark  int
	origInterfaces []*Interface
	crosslinkInterfaces []*Interface
	filterOnly []net.IPNet
	generalPermit []*proto
	needProtect bool
	noGroupCode bool
	noSecondaryOpt map[*Network]bool
	hardware   []*Hardware
	origHardware []*Hardware
	origRouter *Router
	radiusAttributes map[string]string
//	reachablePart map[int]bool
	routingOnly bool
	trustPoint string
	vrfMembers []*Router
	ipV6       bool
	aclList    []*aclInfo
	vrf        string
}
func (x *Router) getName() string { return x.name }

type Interface struct {
	netObj
	pathStoreData
	router  		  *Router
	crypto        *Crypto
	dhcpClient    bool
	dhcpServer    bool
	hub           []*Crypto
	spoke         *Crypto
	id            string
	isHub         bool
	hardware      *Hardware
	loop          *loop
	loopback      bool
	loopEntryZone map[pathStore]pathStore
	loopZoneBorder bool
	mainInterface *Interface
	nat     		  map[string]net.IP
	natSet        natSet
	origMain      *Interface
	pathRestrict  []*pathRestriction
//	reachableAt   map[pathObj][]int
	peer    		  *Interface
	peerNetworks  []*Network
	realInterface *Interface
	redundancyInterfaces []*Interface
	redundancyType string
	redundant     bool
	reroutePermit []someObj
	routes        map[*Interface]map[*Network]bool
	routing       *Routing
	rules         RuleList
	intfRules     RuleList
	outRules      RuleList
	idRules       map[string]*idInterface
	toZone1       pathObj
	zone          *Zone
}
type idInterface struct {
	*Interface
	src *Subnet
}

type Routing struct {
	name   string
	prt    *proto
	mcast  mcastInfo
}

type Xxrp struct {
	prt *proto
	mcast mcastInfo
}

type Hardware struct {
	interfaces  []*Interface
	crosslink   bool
	loopback    bool
	name        string
	natSet      natSet
	dstNatSet   natSet
	needOutAcl  bool
	noInAcl     bool
	rules       RuleList
	intfRules   RuleList
	outRules    RuleList
	ioRules     map[string]RuleList
	subcmd      []string
}

type pathRestriction struct {
	activePath  bool
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
	pathStoreData
	pathObjData
	name     string
	networks []*Network
	attr     map[string]string
	inArea   *Area
	partition     string
//	reachablePart map[int]bool
	zoneCluster []*Zone
}
func (x *Zone) getName() string { return x.name }

type Area struct {
	name     string
	attr     map[string]string
	inArea   *Area
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

type Service struct {
	name             	 string
	disabled         	 bool
	ruleCount        	 int
	duplicateCount   	 int
	redundantCount   	 int
	hasSameDupl      	 map[*Service]bool
	overlaps         	 []*Service
	overlapsUsed     	 map[*Service]bool
	overlapsRestricted bool
}

type UnexpRule struct {
	prt           []protoOrName
	service       *Service
}

type Rule struct {
	deny          bool
	src           []someObj
	dst           []someObj
	prt           ProtoList
	srcRange      *proto
	log           string
	rule          *UnexpRule
	srcPath       pathStore
	dstPath       pathStore
	stateless     bool
	statelessICMP bool
	overlaps      bool
	someNonSecondary bool
	somePrimary   bool
}
type RuleList []*Rule

type PathRules struct {
	permit RuleList
	deny   RuleList
}

type protoOrName interface{}
type ProtoList []*proto

type ProtoGroup struct {
	pairs []protoOrName
	elements ProtoList
	recursive bool
	isUsed bool
}

type mcastInfo struct {
	v4 []string
	v6 []string
}
