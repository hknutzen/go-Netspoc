package pass1

import (
	"time"
)

var version = "devel"

var config Config

var startTime time.Time
var ErrorCounter int

var protocols map[string]*proto
var protocolgroups map[string]*ProtoGroup

var services map[string]*Service

var pathRules *PathRules
