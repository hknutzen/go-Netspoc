package err

import (
	"fmt"
	"os"
)

func Fatal(format string, args ...interface{}) {
	string := "Error: " + fmt.Sprintf(format, args...)
	fmt.Fprintln(os.Stderr, string)
	os.Exit(1)
}
