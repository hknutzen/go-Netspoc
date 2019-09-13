package pass1

import (
	"time"
)

var version = "devel"

var config Config

var startTime time.Time
var ErrorCounter int

var prtIP *proto
var prtBootps *proto
var prtBootpc *proto
var xxrpInfo map[string]*Xxrp

var protocols map[string]*proto
var protocolgroups map[string]*ProtoGroup

var services map[string]*Service

var pathRules *PathRules

var managedRouters []*Router
var routingOnlyRouters []*Router
var zones []*Zone

var outDir string
