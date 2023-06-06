package config

import (
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/posflag"
	"github.com/knadh/koanf/providers/rawbytes"
	"github.com/knadh/koanf/v2"
	flag "github.com/spf13/pflag"
)

var K *koanf.Koanf

const defaultConfig = `
authkeys: "/root/.ssh/authorized_keys"
followauthkeys: false
bucket: "LoginMonitor"
output: "log"
log: "journal"
database: "fingerprints.db"
updatekeys: true
color: false
theme:
  username: green
  eventtype: yellow
  eventtime: red
  sourceip: blue
  starttime: green
  endtime: red
  port: blue`

func LoadKonfig() error {
	var err error
	K = koanf.New(".")
	if err != nil {
		return err
	}

	f := flag.NewFlagSet("config", flag.ContinueOnError)
	configFile := f.StringP("config", "c", "config.yaml", "Configuration file")
	f.StringP("authkeys", "a", "", "authorized_keys file containing public keys")
	f.BoolP("followauthkeys", "k", false, "Follow authorized_keys file")
	f.StringP("bucket", "b", "LoginMonitor", "Database bucket name")
	f.StringP("output", "o", "sum", "Output format: sum, log, csv, json")
	f.StringP("log", "l", "/var/log/secure", "Log file to parse. If no log file is specified, it collects the fingerprints and exits.")
	f.StringP("database", "d", "fingerprints.db", "Fingerprints database")
	f.BoolP("updatekeys", "u", true, "Update keys in database")
	f.BoolP("follow", "f", false, "Watch log file for changes")
	f.Bool("color", false, "Color output")
	if err := f.Parse(os.Args[1:]); err != nil {
		return err
	}

	err = K.Load(rawbytes.Provider([]byte(defaultConfig)), yaml.Parser())
	if err != nil {
		return err
	}

	*configFile = os.ExpandEnv(*configFile) // to be able to use $HOME and other variables
	fmt.Printf("Config file: %s\n", *configFile)

	if err := K.Load(file.Provider(*configFile), yaml.Parser()); err != nil {
		if !errors.Is(err, os.ErrNotExist) { // if the error is something else: bad YAML format, etc.
			return err
		} else {
			log.Println("No config file found. Using defaults...")
		}
	}

	if err := K.Load(posflag.Provider(f, ".", K), nil); err != nil {
		return err
	}
	log.Printf("Using config: %v\n", K.All())

	return nil
}
