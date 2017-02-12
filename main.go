package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/docopt/docopt.go"
	"gopkg.in/yaml.v2"
)

func main() {
	var opts HijackerOptions

	usage := `Usage: wifi-hijack CONFIG

Hijacks DNS requests on the given device.

Arguments:
  CONFIG        configuration file
Options:
  -h --help`

	arguments, _ := docopt.Parse(usage, nil, true, "", false)

	data, err := ioutil.ReadFile(arguments["CONFIG"].(string))

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading config file:\n%s\n", err)
		os.Exit(1)
		return
	}

	if err := yaml.Unmarshal(data, &opts); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading config file:\n%s\n", err)
		os.Exit(1)
		return
	}

	hijacker, err := CreateHijacker(&opts)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating hijacker:\n%s\n", err)
		os.Exit(1)
		return
	}

	err = hijacker.Run()

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error running hijacker:\n%s\n", err)
		os.Exit(1)
		return
	}
}

func run(options *HijackerOptions) error {
	h, err := CreateHijacker(options)

	if err != nil {
		return err
	}

	return h.Run()
}
