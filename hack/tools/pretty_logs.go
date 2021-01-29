// quick tool to read from stdin, expecting JSON client.StreamMessage logs
// e.g., `kubectl logs -l sw-job=<jobname> -f | go run hack/tools/pretty_logs.go`

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"

	"github.com/criticalstack/swoll/pkg/client"
	"github.com/fatih/color"
)

func main() {
	scanner := bufio.NewScanner(os.Stdin)

	for scanner.Scan() {
		var event client.StreamMessage

		b := scanner.Bytes()

		if len(b) == 0 || b[0] == '\n' || b[1] == '\r' {
			continue
		}

		err := json.Unmarshal(b, &event)
		if err != nil {
			continue
		}

		fn := event.Data.Argv
		args := fn.Arguments()

		var errno string

		if event.Data.Error == 0 {
			errno = color.GreenString("OK")
		} else {
			errno = color.RedString(event.Data.Error.String())
		}

		bold := color.New(color.Bold).SprintFunc()
		cyan := color.New(color.FgCyan).SprintFunc()
		green := color.New(color.FgGreen).SprintFunc()

		fmt.Printf("%35s: [%8s] (%11s) %s(", bold(green(event.Data.Container.FQDN())), event.Data.Comm, errno, bold(cyan(fn.CallName())))

		for x, arg := range args {
			fmt.Printf("(%s)%s=%v", bold(arg.Type), arg.Name, bold(arg.Value))

			if x < len(args)-1 {
				fmt.Printf(", ")
			}
		}

		fmt.Printf(")\n")

	}

}
