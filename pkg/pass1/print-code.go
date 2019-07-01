package pass1;

import (
	"fmt"
	"github.com/json-iterator/go"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"github.com/hknutzen/go-Netspoc/pkg/err"
	"github.com/hknutzen/go-Netspoc/pkg/jcode"
)

func isDir(path string) bool {
	stat, err := os.Stat(path)
	return err == nil && stat.Mode().IsDir()
}

func printPrt(prt *proto) string {
	// Use cached result.
	if p := prt.printed; p != "" {
		return p
	}
	proto := prt.proto
	result := proto

	switch proto {
	case "tcp", "udp":
		for _, port := range prt.ports {
			result += " " + strconv.Itoa(port)
		}
		if prt.established {
			result += " established"
		}
	case "icmp", "icmpv6":
		if t := prt.icmpType; t != -1 {
			result += " " + strconv.Itoa(t)
			if c := prt.icmpCode; c != -1 {
				result += " " + strconv.Itoa(c)
			}
		}
	}
	// Cache result.
	prt.printed = result
	return result
}

func isHostMask(m net.IPMask) bool {
	prefix, size := m.Size()
	return prefix == size
}

func prefixCode (n net.IPNet) string {
	prefix, size := n.Mask.Size()
	if prefix == size {
		return n.IP.String()
	}
	return n.IP.String() + "/" + strconv.Itoa(prefix)

}

func fullPrefixCode (n net.IPNet) string {
	prefix, _ := n.Mask.Size()
	return n.IP.String() + "/" + strconv.Itoa(prefix)
}

// Collect interfaces that need protection by additional deny rules.
// Add list to each ACL separately, because IP may be changed by NAT.
func getNeedProtect(r *Router) []*Interface {

	// ASA protects IOS router behind crosslink interface.
	// Routers connected by crosslink networks are handled like one
	// large router. Protect the collected interfaces of the whole
	// cluster at each entry.
	list := r.crosslinkInterfaces
	if list != nil {
		return list
	}
	if !r.needProtect {
		return nil
	}
	for _, i := range r.Interfaces {
		if len(i.IP) == 0 {
			continue
		}
		list = append(list, i)
	}
	return list
}

type natCache struct {
	nat natSet
	cache map[someObj]string
}
var nat2Cache = make(map[natSet]*natCache)

func getAddrCache(n natSet) *natCache {
	if nc, ok := nat2Cache[n]; ok {
		return nc
	}
	nc := natCache{
		nat: n,
		cache: make(map[someObj]string),
	}
	nat2Cache[n] = &nc
	return &nc
}

func getCachedAddr(o someObj, nc *natCache) string {
	if a, ok := nc.cache[o]; ok {
		return a
	}
	a := fullPrefixCode(o.address(nc.nat))
	nc.cache[o] = a
	return a
}

func getCachedAddrList(l []someObj, nc *natCache) []string {
	result := make([]string, len(l))
	for i,o := range l {
		result[i] = getCachedAddr(o, nc)
	}
	return result
}

func printAcls (fh *os.File, vrfMembers []*Router) {
	var aclList []*jcode.ACLInfo
	for _, router := range vrfMembers {
		managed         := router.Managed
		secondaryFilter := strings.HasSuffix(managed, "secondary")
		standardFilter  := managed == "standard"
		model           := router.Model
		doAuth          := model.DoAuth
		activeLog       := router.Log
		needProtect     := getNeedProtect(router)

		process := func(acl *aclInfo) *jcode.ACLInfo {
			jACL := new(jcode.ACLInfo)
			jACL.Name = acl.name
			if acl.addPermit {
				jACL.AddPermit = 1
			}
			if acl.addDeny {
				jACL.AddDeny = 1
			}
			if acl.filterAnySrc {
				jACL.FilterAnySrc = 1
			}
			if acl.isStdACL {
				jACL.IsStdACL = 1
			}
			if acl.isCryptoACL {
				jACL.IsCryptoACL = 1
			}
			// Collect networks used in secondary optimization and
			// cache for address calculation.
			optAddr := make(map[*Network]*natCache)
			// Collect objects forbidden in secondary optimization and
			// cache for address calculation.
			noOptAddrs := make(map[someObj]*natCache)
			natSet := acl.natSet
			addrCache := getAddrCache(natSet)
			dstNatSet := acl.dstNatSet
			if dstNatSet == nil {
				dstNatSet = natSet
			}
			dstAddrCache := getAddrCache(dstNatSet)

			// Set attribute NeedProtect in jACL.
			// Value is list of IP addresses of to be protected interfaces.
			//
			// This possibly generates invalid IP address 0.0.0.0/32 for
			// hidden interface, if some LAN interface is hidden in NAT
			// set of crypto interface.
			// But that doesn't matter, because only IOS routers
			// - need protection of interfaces and
			// - are also used as crypto device.
			// But IOS routers have separate crypto-filter-ACL
			// and therefore these invalid addresses are never used.
			if needProtect != nil && acl.protectSelf {
				// For removing duplicate addresses from redundancy interfaces.
				seen := make(map[string]bool)
				for _, intf := range needProtect {
					a := getCachedAddr(intf, addrCache)
					if !seen[a] {
						seen[a] = true
						jACL.NeedProtect = append(jACL.NeedProtect, a)
					}
				}
			}

			optRules := func(rules []*Rule) []*jcode.Rule {
				jRules := make([]*jcode.Rule, len(rules))
				for i, rule := range rules {
					newRule := new(jcode.Rule)
					jRules[i] = newRule
					if rule.Deny {
						newRule.Deny = 1
					}

					// Add code for logging.
					// This code is machine specific.
					if activeLog != nil && rule.Log != "" {
						logCode := ""
						for _, tag := range strings.Split(rule.Log, ",") {
							if modifier, ok := activeLog[tag]; ok {
								if modifier != "" {
									normalized := model.logModifiers[modifier]
									if normalized == ":subst" {
										logCode = modifier
									} else {
										logCode = "log " + normalized
									}
								} else {
									logCode = "log"
								}
								// Take first of possibly several matching tags.
								break
							}
						}
						newRule.Log = logCode
					}

					if secondaryFilter && rule.someNonSecondary ||
						standardFilter && rule.somePrimary {
						for _, isSrc := range []bool{true, false} {
							var objList []someObj
							var useCache *natCache
							if isSrc {
								objList = rule.Src
								useCache = addrCache
							} else {
								objList = rule.Dst
								useCache = dstAddrCache
							}
							for _, obj := range objList {

								// Prepare secondary optimization.

								// Restrict secondary optimization at
								// authenticating router to prevent
								// unauthorized access with spoofed IP
								// address.
								// It would be sufficient to disable
								// optimization only for incoming
								// traffic. But for a VPN router with
								// only a single interface, incoming
								// and outgoing traffic is mixed at
								// this interface.
								// At this stage, network with
								// attribute hasIdHosts has already been
								// converted to single ID hosts.
								if doAuth {
									if o, ok := obj.(*Subnet); ok {
										if o.id != "" {
											continue
										}
									}
								}

								var subst *Network
								switch o := obj.(type) {
								case *Subnet, *Interface:
									net := obj.network()
									if net.hasOtherSubnet {
										continue
									}
									if noOpt := router.noSecondaryOpt; noOpt != nil {
										if noOpt[net] {
											noOptAddrs[obj] = useCache
											continue
										}
									}
									subst = net
									if max := subst.maxSecondaryNet; max != nil {
										subst = max
									}

									// Ignore loopback network.
									if isHostMask(subst.Mask) {
										continue
									}

									// Network or aggregate.
								case *Network:

									// Don't modify protocol of rule
									// with hasOtherSubnet, because
									// this could introduce new missing
									// supernet rules.
									if o.hasOtherSubnet {
										noOptAddrs[obj] = useCache
										continue
									}
									max := o.maxSecondaryNet
									if max == nil {
										continue
									}
									subst = max
								}
								optAddr[subst] = useCache
							}
						}
						newRule.OptSecondary = 1
					}

					newRule.Src = getCachedAddrList(rule.Src, addrCache)
					newRule.Dst = getCachedAddrList(rule.Dst, dstAddrCache)
					prtList := make([]string, len(rule.Prt))
					for i, p := range rule.Prt {
						prtList[i] = printPrt(p)
					}
					newRule.Prt = prtList
					if srcRange := rule.SrcRange; srcRange != nil {
						newRule.SrcRange = printPrt(srcRange)
					}
				}
				return jRules
			}
			jACL.IntfRules = optRules(acl.intfRules)
			jACL.Rules = optRules(acl.rules)

			// Secondary optimization is done in pass 2.
			// It converts protocol to IP and
			// src/dst address to network address.
			// It is controlled by this three attributes:
			// - OptSecondary enables secondary optimization
			// - if enabled, then networks in OptNetworks are used
			//   for optimization.
			// - if src/dst matches NoOptAddrs, then
			//   optimization is disabled for this single rule.
			//   This is needed because OptSecondary is set for
			//   grouped rules and we need to control optimization
			//   for sinlge rules.
			addrList := make([]string, 0, len(optAddr))
			for n, cache := range optAddr {
				a := getCachedAddr(n, cache)
				addrList = append(addrList, a)
			}
			sort.Strings(addrList)
			jACL.OptNetworks = addrList

			addrList = make([]string, 0, len(noOptAddrs))
			for o, cache := range noOptAddrs {
				a := getCachedAddr(o, cache)
				addrList = append(addrList, a)
			}
			sort.Strings(addrList)
			jACL.NoOptAddrs = addrList
			return jACL
		}

		aref := router.aclList
		router.aclList = nil
		for _, acl := range aref {
			result := process(acl)
			for _, acl := range acl.subAclList {
				subResult := process(acl)
				result.Rules = append(result.Rules, subResult.Rules...)
				result.IntfRules = append(result.IntfRules, subResult.IntfRules...)
				result.OptNetworks =
					append(result.OptNetworks, subResult.OptNetworks...)
				result.NoOptAddrs =
					append(result.NoOptAddrs, subResult.NoOptAddrs...)
			}
			aclList = append(aclList, result)
		}
	}

	router := vrfMembers[0]
	model  := router.Model
	result := &jcode.RouterData{ Model: model.Class, ACLs: aclList }

	if filterOnly := router.filterOnly; filterOnly != nil {
		list := make([]string, len(filterOnly))
		for i, f := range filterOnly {
			list[i] = prefixCode(f)
		}
		result.FilterOnly = list
	}
	if model.canObjectgroup && !router.noGroupCode {
		result.DoObjectgroup = 1
	}
	if router.logDeny {
		result.LogDeny = "log"
	}

	b, err := jsoniter.MarshalIndent(result, "", " ")
	if err != nil {
		panic(err)
	}
	fmt.Fprint(fh, string(b))
}

// Print generated code for each managed router.
func printCode (dir string) {
	progress("Printing ACLs")

	var toPass2 *os.File
	if config.Pipe {
		toPass2 = os.Stdout
	} else {
		devlist := dir + "/.devlist"
		var e error
		toPass2, e = os.Create(devlist)
		if e != nil {
			err.Fatal("Can't %v", e)
		}
	}

	checkedV6dir := false
	seen := make(map[*Router]bool)
	printRouter := func (routers []*Router) {
		for _, router := range routers {
			if seen[router] {
				continue
			}

			// Ignore split part of crypto router.
			if router.OrigRouter != nil {
				continue
			}

			deviceName := router.DeviceName
			path := deviceName
			if router.IPv6 {
				path = "ipv6/" + path
				v6dir := dir + "/ipv6"
				if !checkedV6dir && !isDir(v6dir) {
					checkedV6dir = true
					e := os.Mkdir(v6dir, 0777)
					if e != nil {
						err.Fatal("Can't %v", e)
					}
				}
			}

			// Collect VRF members.
			vrfMembers := router.VrfMembers
			if vrfMembers == nil {
				vrfMembers = []*Router{router}
			}
/*
			// File for router config without ACLs.
			configFile := fmt.Sprintf("dir/%s.config", path)
			fd, err := os.Open(configFile)
			if err != nil {
				fatalErr("Can't open %s: %s", configFile, err)
			}
			model := router.Model
			commentChar := model.CommentChar

			// Restore interfaces of split router.
			if orig := router.OrigInterfaces; orig != nil {
				router.Interfaces = orig
				router.Hardware   = router.OrigHardware
			}

			// Print version header.
			fmt.Fprintf(fd, "%s Generated by program, version %s\n\n",
				commentChar, version)

			printHeader := func(key, val string) {
				fmt.Fprintf(fd, "%s [ %s %s ]\n", commentChar, key, val)
			}
			printHeader("BEGIN", deviceName)
			printHeader("Model =", model.Class)
			ips := make([]string, 0, len(vrfMembers))
			for _, r := range vrfMembers {
				if r.AdminIP != "" {
					ips = append(ips, r.AdminIP)
				}
			}
			if len(ips) != 0 {
				printHeader("IP =", strings.Join(ips, ","))
			}
*/
			for _, vrouter := range vrfMembers {
				seen[vrouter] = true
/*
				printRoutes(fd, vrouter)
				if vrouter.Managed == "" {
					continue
				}
				printCrypto(fd, vrouter)
				printAclPrefix(fd, vrouter)
				generateAcls(fd, vrouter)
				printAclSuffix(fd, vrouter)
				printInterface(fd, vrouter)
*/
			}
/*
			printHeader("END", deviceName)
			if err := fd.Close(); err != nil {
				fatalErr("Can't close %s: %v", configFile, err)
			}
*/
			// Print ACLs in machine independent format into separate file.
			// Collect ACLs from VRF parts.
			aclFile := dir + "/" + path + ".rules"
			aclFd, e := os.Create(aclFile)
			if e != nil {
				err.Fatal("Can't %v", e)
			}
			printAcls(aclFd, vrfMembers)
			if e := aclFd.Close(); e != nil {
				err.Fatal("Can't close %s: %v", aclFile, e)
			}

			// Send device name to pass 2, showing that processing for this
			// device can be started.
			fmt.Fprintln(toPass2, path)
		}
	}
	printRouter(managedRouters)
	printRouter(routingOnlyRouters)
}

func PrintCode () {
	printCode(outDir);
}
