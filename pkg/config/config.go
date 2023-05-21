package config

import (
	"log"
	"os"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/posflag"
	"github.com/knadh/koanf/v2"
	flag "github.com/spf13/pflag"
)

var K *koanf.Koanf

func LoadKonfig(configFile string) error {
	var err error
	K = koanf.New(".")
	if err != nil {
		return err
	}

	if err := K.Load(file.Provider(configFile), yaml.Parser()); err != nil {
		return err
	}
	f := flag.NewFlagSet("config", flag.ContinueOnError)

	f.StringP("authkeys", "a", "", "authorized_keys file containing public keys")
	f.StringP("bucket", "b", "LoginMonitor", "Bucket name")
	f.StringP("output", "o", "sum", "Output format: sum, log, csv, json")
	f.StringP("log", "l", "", "Log file to parse. If no log file is specified, it collects the fingerprints and exits.")
	f.StringP("database", "d", "fingerprints.db", "Fingerprints database")
	f.BoolP("follow", "f", false, "Watch log file for changes")
	f.BoolP("color", "c", false, "Color output")
	if err := f.Parse(os.Args[1:]); err != nil {
		log.Fatal(err)
	}

	if err := K.Load(posflag.Provider(f, ".", K), nil); err != nil {
		log.Fatal(err)
	}

	return nil
}
