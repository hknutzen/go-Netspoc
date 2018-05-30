package main

/*
Get arguments and options from command line and config file.

=head1 COPYRIGHT AND DISCLAIMER

(C) 2018 by Heinz Knutzen <heinz.knutzen@googlemail.com>

http://hknutzen.github.com/Netspoc

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

import (
	"fmt"
	"io/ioutil"
	"regexp"
	"strings"
	"os"
	"strconv"
	flag "github.com/spf13/pflag"
	"github.com/octago/sflags"
	"github.com/octago/sflags/gen/gpflag"
)

// Type for command line flag with value 0|1|warn
type triState string
func (v *triState) String () string { return string(*v) }
func (v *triState) Set (s string) error {
	switch strings.ToLower(s) {
	case "0", "no", "f", "false":
		*v = "no"
	case "1", "e", "err", "error":
		*v = "err"
	case "w", "warn", "warning":
		*v = "warn"
	default:
		return fmt.Errorf("Expected 0|1|warn but got %s", s)
	}
	return nil
}
// Needed for gen/gpflag to work, mostly for pflag compatibility.
func (v triState) Type() string { return "tristate" }

// Type for additional name to existing flag with inverted boolean value.
type invFlag struct { flag *flag.Flag }
func (v invFlag) String () string {
	b, _ := strconv.ParseBool(v.flag.Value.String())
	return strconv.FormatBool(!b)
}
func (v invFlag) Set (s string) error {
	b, err := strconv.ParseBool(s)
	if err != nil {
		return err
	}
	inverted := strconv.FormatBool(!b)
	v.flag.Value.Set(inverted)
	return nil
}
func (v invFlag) Type() string { return "invFlag" }

// Config holds program flags.
type Config struct {
	CheckUnusedGroups triState
	CheckUnusedOwners triState
	CheckUnusedProtocols triState
	CheckSubnets triState
	CheckUnenforceable triState
	CheckDuplicateRules triState
	CheckRedundantRules triState
	CheckFullyRedundantRules triState
	CheckServiceUnknownOwner triState
	CheckServiceMultiOwner triState
	CheckSupernetRules triState
	CheckTransientSupernetRules triState
	CheckPolicyDistributionPoint triState
	AutoDefaultRoute bool 
	ConcurrencyPass1 int
	ConcurrencyPass2 int
	IgnoreFiles *regexp.Regexp
	Ipv6 bool       `flag:"ipv6 6"`
	MaxErrors int   `flag:"max_errors m"`
	Verbose bool    `flag:"verbose v"`
	TimeStamps bool `flag:"time_stamps t"`
	StartTime int64
	Pipe bool
}

type invertedFlag map[string]*struct {
	short string
	orig string
}

var invertedFlags = invertedFlag{
	"quiet": { short: "q", orig: "verbose" },
	// For compatibilty with Perl Getopt::Long
	"noauto_default_route": { orig: "auto_default_route" },
}
	
func parseOptions() *Config {
	cfg := &Config{
		
		// Check for unused groups and protocolgroups.
		CheckUnusedGroups: "warn",

		// Check for unused owners.
		CheckUnusedOwners: "warn",

		// Check for unused protocol definitions.
		CheckUnusedProtocols: "no",
		
		// Allow subnets only
		// if the enclosing network is marked as 'has_subnets' or
		// if the subnet is marked as 'subnet_of'
		CheckSubnets: "warn",
		// Check for unenforceable rules, i.e. no managed device between
		// src and dst.
		CheckUnenforceable: "warn",

		// Check for duplicate rules.
		CheckDuplicateRules: "warn",

		// Check for redundant rules.
		CheckRedundantRules: "warn",
		CheckFullyRedundantRules: "no",

		// Check for services where owner can't be derived.
		CheckServiceUnknownOwner: "no",

		// Check for services where multiple owners have been derived.
		CheckServiceMultiOwner: "warn",

		// Check for missing supernet rules.
		CheckSupernetRules: "warn",

		// Check for transient supernet rules.
		CheckTransientSupernetRules: "warn", 

		// Check, that all managed routers have attribute
		// 'policy_distribution_point', either directly or from inheritance.
		CheckPolicyDistributionPoint: "no",

		// Optimize the number of routing entries per router:
		// For each router find the hop, where the largest
		// number of routing entries points to
		// and replace them with a single default route.
		// This is only applicable for internal networks
		// which have no default route to the internet.
		AutoDefaultRoute: true,

		// Ignore these names when reading directories:
		// - CVS and RCS directories
		// - CVS working files
		// - Editor backup files: emacs: *~
		IgnoreFiles: regexp.MustCompile("^(CVS|RCS|\\.#.*|.*~)$"),
		// Use IPv4 version as default
		Ipv6: false,

		// Set value to >= 2 to start concurrent processing.
		ConcurrencyPass1: 1,
		ConcurrencyPass2: 1,

		// Abort after this many errors.
		MaxErrors: 10,

		// Print progress messages.
		Verbose: true,

		// Print progress messages with time stamps.
		// Print "finished" with time stamp when finished.
		TimeStamps: false,

		// Use this value when printing passed time span.
		StartTime: 0,

		// Pass 1 writes processed device names to STDOUT,
		// pass 2 reads to be processed device names from STDIN.
		Pipe: false,
	}
	err := gpflag.ParseToDef(cfg, sflags.FlagDivider("_"))
	if err != nil {
		panic(err)
	}
	for name, spec := range invertedFlags {
		origFlag := flag.Lookup(spec.orig)
		inverted := invFlag{origFlag}
		flag := flag.CommandLine.VarPF(inverted, name, spec.short, "")
		flag.NoOptDefVal = "true"
	}
	flag.Parse()
	return cfg
}


// Read names of input file/directory and output directory from
// passed command line arguments.
func parseArgs() (string, string) {
	mainFile := flag.Arg(0)
	if mainFile == "" || flag.Arg(2) != "" {
		fatalErr("Expected 2 args, got %v", flag.Args())
		flag.Usage()
		os.Exit(2)
	}

	// outDir is used to store compilation results.
	// For each managed router with name X a corresponding file X
	// is created in outDir.
	// If outDir is missing, no code is generated.
	outDir := flag.Arg(1)

	// Strip trailing slash for nicer messages.
	strings.TrimSuffix(mainFile, "/")
	strings.TrimSuffix(outDir, "/")
	return mainFile, outDir
}

// Reads "key = value;" pairs from config file.
// Trailing ";" is optional.
// Comment lines starting with "#" are ignored.
func readConfig(filename string) map[string]string {
	bytes, err := ioutil.ReadFile(filename)
	if err != nil {
		fatalErr("Failed to read config file %s: %s", filename, err)
	}
	lines := strings.Split(string(bytes), "\n")
	result := make(map[string]string)
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || trimmed[0] == '#' {
			continue
		}
		parts := strings.Split(line, "=")
		if len(parts) != 2 {
			fatalErr("Unexpected line in %s: %s", filename, line)
		}
		key, val := parts[0], parts[1]
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		val = strings.TrimSuffix(val, ";")
		result[key] = val
	}
	return result
}

// parseFile parses the specified configuration file and populates unset flags
// in flag.CommandLine based on the contents of the file.
// Hidden flags are not set from file.
func parseFile(filename string) {
	flags := flag.CommandLine
	isSet := make(map[*flag.Flag]bool)
	config := readConfig(filename)

	flags.Visit(func(f *flag.Flag) {
		isSet[f] = true
	})
	flags.VisitAll(func(f *flag.Flag) {
		// Ignore inverted flags.
		if _, found := invertedFlags[f.Name]; found {
			return
		}
		val, found := config[f.Name]
		if !found {
			return
		}
		delete(config, f.Name)
		if isSet[f] {
			return
		}
		err := f.Value.Set(val)
		if err != nil {
			fatalErr("Invalid value for %s in %s: %s", f.Name, filename, val)
		}
	})

	for name, _ := range config {
		fatalErr("Invalid keyword in %s: %s", filename, name)
	}
}

func addConfigFromFile (inDir string) {
	file := inDir + "/config"
	if !isRegular(file) {
		return
	}
	parseFile(file)
}

func getArgs() (*Config, string, string) {

	// Setup custom usage function.
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr,
			"Usage: %s [options] IN-DIR|IN-FILE [CODE-DIR]\n", os.Args[0])
		flag.PrintDefaults()
	}

	conf := parseOptions()
	inPath, outDir := parseArgs()
	addConfigFromFile(inPath)
	return conf, inPath, outDir
}
