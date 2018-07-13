package main

import (
	"os"
	"fmt"
	"regexp"
)

var types = map[string]int {
	"router"          : 1,
	"network"         : 1,
	"host"            : 1,
	"any"             : 1,
	"group"           : 1,
	"area"            : 1,
	"service"         : 1,
	"owner"           : 1,
	"protocol"        : 1,
	"protocolgroup"   : 1,
	"pathrestriction" : 1,
	"nat"             : 1,
	"isakmp"          : 1,
	"ipsec"           : 1,
	"crypto"          : 1,
}

// NAT is applied with bind_nat.
// Owner is optionally referenced as sub_owner.
// Interface definition uses network name.
var aliases = map[string][]string {
	"nat"     : {"bind_nat"},
	"owner"   : {"sub_owner"},
	"network" : {"interface"},
}

var subst = map[string]map[string]string{}

func fatal_err(error string) {
	fmt.Fprintln(os.Stderr, error)
	os.Exit(1)
}

// Alt: Fill %subst with mapping from search to replace for given type.
func setup_subst(object string, search string, replace string) {
	if types[object] != 1 {
		fatal_err("Unknown type " + object)
	}

	subst[object] = map[string]string{ search : replace }

	for _, other := range aliases[object] {
		subst[other] = map[string]string{ search : replace, }
	}

   // Mark additinal types as valid for substitution.
	// Meike: initialisiere leere map - wofür?
	if object == "network" {
		_, ok := subst["interface"]
		if ok == false {
			subst["interface"] = map[string]string{}
		}
		_, ok = subst["host"]
		if ok == false {
			subst["host"] = map[string]string{}
		}
	}
	if object == "router" {
		_, ok := subst["interface"]
		if ok == false {
			subst["interface"] = map[string]string{}
		}
	}

}


func get_type_and_name(object string) (string, string){
	r, err := regexp.Compile(`^(\w+):(.*)$`)
	if err != nil {
		fmt.Printf("Meike: Was mache ich jetzt?\n")
	}
	res := r.FindStringSubmatch(object)
	if len(res) != 3 {
		fatal_err("Missing type in " + object)
	}
	return res[1], res[2]
}


func setup_pattern () {

	for i := 1; i < len(os.Args); i++ {
		old := os.Args[i]
		i++
		if i >= len(os.Args) {
			fatal_err("Missing replace string " + old)
		}
		new := os.Args[i]

		old_type, old_name := get_type_and_name(old)
		new_type, new_name := get_type_and_name(new)
		if old_type != new_type {
			fatal_err("Types must be identical in\n - " + old + "\n - " + new)
		}

		fmt.Println(old_type, old_name, new_name)
		setup_subst(old_type, old_name, new_name)
	}

}

func main() {
	//fehlt: read_pattern(from_file) if from_file;

	if len(os.Args) > 1 {
		setup_pattern()
   }
//	var args [] string = os.Args
//	var old, new string = args[1:1], args[2:2]
//	fmt.Println(args[1:])
//	n : = args[2:]
//	if (new == nil) {
//		fatal_err("Missing replace string", old)
//	}

//	fmt.Println(args[1:])
	//setup_pattern()
}
