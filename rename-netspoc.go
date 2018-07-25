package main

import (
	"os"
	"io/ioutil"
	"fmt"
	"regexp"
	"bufio"
	"path/filepath"
)

type fn func(string)

// Stuff from GetArgs.pm

var config = map[string]string {
	// Use IPv4 version as default.
	"ipv6" : "0",

	// Check for unused groups & protocolgroups.
	"check_unused_groups" : "warn",

	// Check for unused owners.
	"check_unused_owners" : "warn",

	// Check for unused protocol definitions.
	"check_unused_protocols" : "0",

	// Allow subnets only
	// - if the enclosing network is marked as 'has_subnets' or
	// - if the subnet is marked as 'subnet_of'
	"check_subnets" : "warn",

	// Check for unenforceable rules, i.e. no managed device between src and dst.
	"check_unenforceable" : "warn",

	// Check for duplicate rules.
	"check_duplicate_rules" : "warn",

	// Check for redundant rules.
	"check_redundant_rules" : "warn",
	"check_fully_redundant_rules" : "0",

	// Check for services where owner can't be derived.
	"check_service_unknown_owner" : "0",

	// Check for services where multiple owners have been derived.
	"check_service_multi_owner" : "warn",

	// Check for missing supernet rules.
   "check_supernet_rules" : "warn",

	// Check for transient supernet rules.
	"check_transient_supernet_rules" : "warn",

	// Check, that all managed routers have attribute
	// 'policy_distribution_point', either directly or from inheritance.
	"check_policy_distribution_point" : "0",

	// Optimize the number of routing entries per router:
	// For each router find the hop, where the largest
	// number of routing entries points to
	// and replace them with a single default route.
	// This is only applicable for internal networks
	// which have no default route to the internet.
	"auto_default_route" : "1",

	// Ignore these names when reading directories:
	// - CVS and RCS directories
	// - CVS working files
	// - Editor backup files: emacs: *~
   "ignore_files" : "^(CVS|RCS|\\.#.*|.*~)$",

	// Set value to >= 2 to start concurrent processing.
   "concurrency_pass1" : "1",
	"concurrency_pass2" : "1",

	// Abort after this many errors.
	"max_errors" : "10",

	// Print progress messages.
	"verbose" : "1",

	// Print progress messages with time stamps.
	// Print "finished" with time stamp when finished.
	"time_stamps" : "0",

	// Use this value when printing passed time span.
	"start_time" : "0",

	// Pass 1 writes processed device names to STDOUT,
	// pass 2 reads to be processed device names from STDIN.
	"pipe" : "0",
}

func valid_config_key(key string) bool {
    _, ok := config[key]
    return ok;
}

// Key is prefix or string "_default".
// Value is pattern for checking valid values.
var config_type = map[string]string {
	"check_"   : "0|1|warn",
	"max_"     : "\\d+",
	"start_"   : "\\d+",
	"concurr"  : "\\d+",
	"ignore_"  : "\\S+",
	"_default" : "0|1",
}

func get_config_pattern(key string) string {

	for prefix, pattern := range config_type {
		r := regexp.MustCompile("^" +prefix)
		if r.MatchString(key) {
			return pattern
		}
	}
    return config_type["_default"];
}

func check_config_pair (key string, value string) string {

	pattern := get_config_pattern(key);
	r := regexp.MustCompile("^" + pattern)
	if r.MatchString(value) {
		return pattern
	}
   return ""
}

// Stuff from File.pm
var current_file string

func is_dir (path string) bool {
	if fileinfo, err := os.Stat(path); err == nil {
		if fileinfo.Mode().IsDir() {
            return true
        }
	}
	return false
}

// Read input from file and process it by function which is given as argument.
func process_file (path string, parser fn){

	content, err := ioutil.ReadFile(path)
	if err != nil {
		fatal_err("Can't open " + path + ":")
	}
	input := string(content)
	current_file = path
	parser(input)
}

func process_file_or_dir (path string, parser fn) {

	// Handle toplevel file.
	if is_dir(path) == false {
		fmt.Println(path + " is no dir")
		process_file(path, parser)
        return;
	} else {
		// Handle toplevel Directory
		files, err := ioutil.ReadDir(path)
		for _, file := range files {
			fmt.Println("FILE: " + file.Name())

			// skip special files
			if  (!file.Mode().IsDir() &&
				(file.Name() == "config" || file.Name() == "raw" )) {
				fmt.Printf("skipping %s\n", file.Name())
				continue
			}

			//
			hidden := regexp.MustCompile(`^\.`)
			if (!file.Mode().IsDir() && hidden.MatchString(file.Name())) {
				fmt.Printf("skipping %s\n", file.Name())
				continue
			}

			// skip ignored files
			ignore := regexp.MustCompile(config["ignore_files"])
			if (!file.Mode().IsDir() && ignore.MatchString(file.Name())) {
				fmt.Printf("skipping %s\n", file.Name())
				continue
			}

			//			if file.Mode().IsDir() {
			subpath := path + "/" + file.Name()
				err = filepath.Walk(subpath,
					func(subpath string, file os.FileInfo, err error) error {

						// Error - handling
						if err != nil {
							fmt.Printf("prevent panic by handling failure accessing a path %q: %v\n", subpath, err)
							return err
						}

						// ipv4/ipv6 subdir or file specification and private are not used
						// within rename-netspoc

						//skip hidden files
						hidden := regexp.MustCompile(`^\.`)
						if hidden.MatchString(file.Name()) {
							fmt.Printf("skipping %s\n", file.Name())
							return nil
						}

						// skip ignored files
						ignore := regexp.MustCompile(config["ignore_files"])
						if ignore.MatchString(file.Name()) {
							fmt.Printf("skipping %s\n", file.Name())
							return nil
						}

						fmt.Printf("visited: %q\n", subpath)
						if is_dir(subpath) == false {
							fmt.Println("processing file " + subpath)
							process_file(subpath, parser)
						}
						return nil
					})

				if err != nil {
					fmt.Printf("error walking the path %q: %v\n", subpath, err)
				}
//		}

		}
	}
}


// Stuff from Common.pm

func info (info string) {
//    return if not $config->{verbose};
    fmt.Fprintln(os.Stderr, info)
}
// Ende



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

func read_file_lines (path string) []string {
	file, err := os.Open(path)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	file.Close()

	return lines

}

// Read key value pairs from file '$path/config' if file exists.
func read_config (dir string) map[string]string {

	var result = map[string]string {}
	filename := dir + "/config"

	_, err := os.Stat(filename)
	if err != nil {
		return result
	}

	lines := read_file_lines(filename)
	skip := regexp.MustCompile(`(^\s*#|^\s*$)`)
	keep := regexp.MustCompile(`\s*(\w+)\s*=\s*(\S+);`)

	for _, line := range lines {
		if skip.MatchString(line) {
			continue
		}
		pair := keep.FindStringSubmatch(line)
		if len(pair) == 3 {
			key := pair[1]
			value := pair[2]

			if valid_config_key(key) == false {
				fatal_err("Invalid keyword in " + filename + ": " + key)
			}

			expected := check_config_pair(key, value)
			if expected == "" {
				fatal_err("Invalid value for " + key + " in " + filename + "," +
                          " expected '$expected'");
			}
			result[key] = value
		} else {
			fatal_err("Unexpected line in " + filename + ": " + line)
		}
	}
	return result
}

// Fill subst with mapping from search to replace for given type.
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

func substitute (object string, name string) string {
	replace, ok :=  subst[object][name]
	if !ok  {
		return name
	}

	//ID host is extended by network name.
	if object == "host" {
		re := regexp.MustCompile(`^(id:.*)[.]([\w-]+)$`)
		if re.MatchString(name) {
			str := re.FindStringSubmatch(name)
			host := str[1]
			network := str[2]
			r, o :=  subst["host"][host]
			if o {
				host = r
				name = host + "." + network
			}
			r, o =  subst["network"][host]
			if o {
				network = r
				name = host + "." + network

			}
			return name
		}
	}
	// Reference to interface ouside the definition of router.
	if object == "interface" {
		re := regexp.MustCompile(`^([\w@-]+)[.]([\w-]+)((?:[.].*)?)$`)
		if re.MatchString(name) {
			str := re.FindStringSubmatch(name)
			router := str[1]
			network := str[2]
			ext := str[3]
			repl, exists :=  subst["router"][router]
			if exists {
				router = repl
				name = router + "." + network + ext
			}
			repl, exists = subst["network"][network]
			if exists {
				network = repl
				name = router + "." + network + ext
			}
			return name
		}
	}
	return replace
}

func match(pattern *regexp.Regexp, string string, index int) ([]string, int) {
	str := pattern.FindStringSubmatch(string)
	loc := pattern.FindStringIndex(string)
	return str, loc[1]
}

func process(input string) (int, string) {
	changed := 0
	copy := ""

	// Iteratively parse inputstring
	comment := regexp.MustCompile(`(^\s*[#].*\n)`)
	nothing := regexp.MustCompile(`^.*\n`)
	declaration := regexp.MustCompile(`^(.*?)(\w+)(:)([-\w.\@:]+)`)
	list := regexp. MustCompile(`^(.*?)([-\w]+)(\s* = [ \t]*)`)
	listelem := regexp.MustCompile(`^(\s*)([-\w.\@:ßüaö]+)`)
	comma := regexp.MustCompile(`^(\s*,\s*)`)

	typelist := ""
	index := 0
	var str []string

	for index < len(input) {
		input = input[index:]

	if comment.MatchString(input) {
		str, index = match(comment, input, index)
			copy += str[0]
			continue
		}
		if typelist != "" {
			if listelem.MatchString(input) {
				str, index = match(listelem, input, index)
				name := str[2]
				new := substitute(typelist, name)
				copy += new
				if new != name {
					fmt.Printf ("substitute %s with %s\n", name, new)
					changed++
				}
				continue
			}
			if comma.MatchString(input) {
				str, index = match(comma, input, index)
				copy += str[0]
				continue
			}
			typelist = ""
		}

		if declaration.MatchString(input) {
			str, index = match(declaration, input, index)
			copy += str[1]+str[2]+str[3]
			object := str[2]
			name := str[4]
			new := substitute(object, name)
			copy += new
			if new != name {
				changed++
			}
			continue
		}
		if list.MatchString(input) {
			str, index = match(list, input, index)
			copy += str[1]+str[2]+str[3]
			object := str[2]
			if subst[object] != nil {
				typelist = str[2]
			}
			continue
		}
		if nothing.MatchString(input) {
			str, index = match(nothing, input, index)
			copy += str[0]
			continue
		}
		break
	}

	fmt.Println(copy) // Meike
	fmt.Printf("Changed %d namse\n", changed) // Meike
	return changed, copy
}

//sub process_input {
func process_input (input string) {
	count, copy := process(input)
	if count == 0 {
		return
	}

   path := current_file;
	info(string(count) + "changes in " + path) // if not $quiet;
	err := os.Remove(path)
	if err != nil {
		fatal_err("Can't remove " + path + ": " + err.Error())
	}
	file, err := os.Create(path)
	if err != nil {
		fatal_err("Can't create " + path + ": " + err.Error())
	}
	_, err = file.WriteString(copy)
	if err != nil {
		fatal_err("Can't write to " + path + ": " + err.Error())
	}
	file.Close()
}

func get_type_and_name(object string) (string, string){
	r := regexp.MustCompile(`^(\w+):(.*)$`)
	res := r.FindStringSubmatch(object)
	if len(res) != 3 {
		fatal_err("Missing type in " + object)
	}
	return res[1], res[2]
}

func setup_pattern () {

	for i := 2; i < len(os.Args); i++ {
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
	if len(os.Args) < 2 { //prog, path. pairs optional, needs fromfile flag.
		fmt.Println("Usage-Meldung!")
		// Usage-Meldung!
	}

	// Argument processing
	path := os.Args[1]


	// Initialize search/replace pairs.
	//	read_pattern($from_file) if $from_file;
	if len(os.Args) > 2 { // pairs specified
		setup_pattern()
	}
	// Initialize $config, especially 'ignore_files'.
	//	my $file_config = read_config($path);
	file_config := read_config(path)
	for key, value := range file_config {
		fmt.Println("key " + key + " value " + value)
	}
//	$config = combine_config($file_config, {verbose => !$quiet});

	// Do substitution.
	process_file_or_dir(path, process_input)
}
