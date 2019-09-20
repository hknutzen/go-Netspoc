package filetree

import (
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"
	"github.com/hknutzen/go-Netspoc/pkg/conf"
	"github.com/hknutzen/go-Netspoc/pkg/err"
	"github.com/hknutzen/go-Netspoc/pkg/fileop"
)

type Context struct {
	Path string
	Data string
	ipV6 bool
	private string
}
type parser func(*Context)

// Read input from file and process it by function which is given as argument.
func processFile(input *Context, fn parser) {
	content, e := ioutil.ReadFile(input.Path)
	if e != nil {
		err.Fatal("Can't read %s: %s", input.Path, e)
	}
	input.Data = string(content)
	fn(input)
}

func Process(fname string, fn parser) {
	input := &Context{ipV6: conf.Conf.IPV6}

	// Handle toplevel file.
	if !fileop.IsDir(fname) {
		input.Path = fname
		processFile(input, fn)
		return;
	}

	// Handle toplevel Directory
	files, e := ioutil.ReadDir(fname)
	if e != nil {
		panic(e)
	}
	ipvDir := "ipv6"
	if conf.Conf.IPV6 {
		ipvDir = "ipv4"
	}
	for _, file := range files {
		name := file.Name()
		base := path.Base(name)
		ignore := conf.Conf.IgnoreFiles
		// Skip hidden file, special file/directory, ignored file.
		if base[0] == '.' || base == "config" || base == "raw" ||
			ignore.MatchString(base) {
			continue
		}
		e = filepath.Walk(name,
			func(fname string, file os.FileInfo, e error) error {
				if e != nil {
					// Abort filepath.Walk.
					return e
				}
				copy := *input
				input := &copy
				input.Path = fname

				base := path.Base(fname)

				// Handle ipv6 / ipv4 subdirectory or file.
				if base == ipvDir {
					input.ipV6 = base == "ipv6"
				}

				// Handle private directories and files.
				if strings.HasSuffix(base, ".private") {
					if input.private != "" {
						err.Fatal("Nested private context is not supported:\n %s",
							fname);
					}
					input.private = base
            }

				// Skip hidden and ignored file.
				if base[0] == '.' || ignore.MatchString(base) {
					return nil
				}

				if !file.IsDir() {
					processFile(input, fn)
				}
				return nil
			})

		if e != nil {
			err.Fatal("while walking path %q: %v\n", fname, e)
		}
	}
}
