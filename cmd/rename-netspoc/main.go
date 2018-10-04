package main

import (
	"os"
	"io/ioutil"
	"github.com/spf13/pflag"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"github.com/hknutzen/go-Netspoc/pkg/err"
	"github.com/hknutzen/go-Netspoc/pkg/diag"
	"github.com/hknutzen/go-Netspoc/pkg/conf"
	fileop "github.com/hknutzen/go-Netspoc/pkg/file"
)

type fn func(string)

var currentFile string

// Read input from file and process it by function which is given as argument.
func processFile (path string, parser fn){

	content, e := ioutil.ReadFile(path)
	if e != nil {
		err.Fatal("Can't read %s: %s", path, e.Error())
	}
	input := string(content)
	currentFile = path
	parser(input)
}

func processFileOrDir (path string, parser fn) {

	// Handle toplevel file.
	if fileop.IsDir(path) == false {
		processFile(path, parser)
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
			ignore := conf.Conf.IgnoreFiles
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
						ignore := conf.Conf.IgnoreFiles
						if ignore.MatchString(file.Name()) {
							fmt.Printf("skipping %s\n", file.Name())
							return nil
						}

						fmt.Printf("visited: %q\n", subpath)
						if fileop.IsDir(subpath) == false {
							fmt.Println("processing file " + subpath)
							processFile(subpath, parser)
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

// NAT is applied with bindNat.
// Owner is optionally referenced as subOwner.
// Interface definition uses network name.
var aliases = map[string][]string {
	"nat"     : {"bindNat"},
	"owner"   : {"subOwner"},
	"network" : {"interface"},
}

var subst = map[string]map[string]string{}

// Fill subst with mapping from search to replace for given type.
func setupSubst(object string, search string, replace string) {
	if types[object] != 1 {
		err.Fatal("Unknown type %s", object)
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

	return changed, copy
}

//sub processInput {
func processInput (input string) {
	count, copy := process(input)
	if count == 0 {
		return
	}

   path := currentFile;
	diag.Info("%d changes in %s", count, path)
	e := os.Remove(path)
	if e != nil {
		err.Fatal("Can't remove %s: %s", path, e.Error())
	}
	file, e := os.Create(path)
	if e != nil {
		err.Fatal("Can't create %s: %s", path, e.Error())
	}
	_, e = file.WriteString(copy)
	if e != nil {
		err.Fatal("Can't write to %s: %s", path, e.Error())
	}
	file.Close()
}

func getTypeAndName(object string) (string, string){
	r := regexp.MustCompile(`^(\w+):(.*)$`)
	res := r.FindStringSubmatch(object)
	if len(res) != 3 {
		err.Fatal("Missing type in '%s'", object)
	}
	return res[1], res[2]
}

func setupPattern (pattern []string) {
	for len(pattern) > 0 {
		old := pattern[0]
		if len(pattern) < 2 {
			err.Fatal("Missing replace string for '%s'", old)
		}
		new := pattern[1]
		pattern = pattern[2:]

		oldType, oldName := getTypeAndName(old)
		newType, newName := getTypeAndName(new)
		if oldType != newType {
			err.Fatal("Types must be identical in\n -%s\n -%s", old, new)
		}
		setupSubst(oldType, oldName, newName)
	}
}

func readPattern(path string) {
	bytes, e := ioutil.ReadFile(path)
	if e != nil {
		err.Fatal("Failed to read file %s: %s", path, e.Error())
	}
	pattern := strings.Fields(string(bytes))
	if len(pattern) == 0 {
		err.Fatal("Missing pattern in %s", path)
	}
	setupPattern(pattern);
}

func main() {

	// Setup custom usage function.
	pflag.Usage = func() {
		fmt.Fprintf(os.Stderr,
			"Usage: %s [options] FILE|DIR SUBSTITUTION ...\n", os.Args[0])
		pflag.PrintDefaults()
	}

	// Command line flags
	quiet := pflag.BoolP("quiet", "q", false, "Don't show number of changes")
	fromFile := pflag.StringP("file", "f", "", "Read pairs from file")
	pflag.Parse()

	// Argument processing
	args := pflag.Args()
	if len(args) == 0 {
		pflag.Usage()
		os.Exit(1)
	}
	inPath := args[0]

	// Initialize search/replace pairs.
	if *fromFile != "" {
		readPattern(*fromFile)
	}
	if len(args) > 1 {
		setupPattern(args[1:])
	}
	// Initialize Conf, especially attribute IgnoreFiles.
	dummyArgs := []string{ fmt.Sprintf("--verbose=%v", !*quiet) }
	conf.ConfigFromArgsAndFile(dummyArgs, inPath)

	// Do substitution.
	processFileOrDir(inPath, processInput)
}
