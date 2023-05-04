package main

import (
	"fmt"
	"log"
	"os"

	"github.com/pavelanni/ssh-login-monitor/pkg/sshloginmonitor"
	flag "github.com/spf13/pflag"
	bolt "go.etcd.io/bbolt"
)

func main() {
	authKeys := flag.StringP("authkeys", "a", "", "authorized_keys file containing public keys")
	bucketName := flag.StringP("bucket", "b", "LoginMonitor", "Bucket name")
	outputFormat := flag.StringP("output", "o", "sum", "Output format: sum, log, csv, json")
	logFile := flag.StringP("log", "l", "", "Log file to parse. If no log file is specified, it collects the fingerprints and exits.")
	dbFile := flag.StringP("database", "d", "fingerprints.db", "Fingerprints database")
	colorFlag := flag.BoolP("color", "c", false, "Color output")
	needHelp := flag.BoolP("help", "h", false, "This help message")
	flag.Parse()

	if *needHelp {
		flag.Usage()
		os.Exit(1)
	}

	db, err := bolt.Open(*dbFile, 0600, nil)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(*bucketName))
		if err != nil {
			return fmt.Errorf("create bucket: %s", err)
		}
		return nil
	})
	if err != nil {
		log.Fatal(err)
	}

	if *authKeys != "" {
		users := make([]sshloginmonitor.User, 0)

		f, err := os.Open(*authKeys)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()

		err = sshloginmonitor.GetAuthKeys(f, &users)
		if err != nil {
			log.Fatal(err)
		}
		err = sshloginmonitor.AddUsersToDB(users, db, *bucketName)
		if err != nil {
			log.Fatal(err)
		}
	}

	if *logFile == "" {
		fmt.Println("No log file specified. Exiting...")
		os.Exit(1)
	}

	logF, err := os.Open(*logFile)
	if err != nil {
		log.Fatal(err)
	}
	defer logF.Close()

	events, err := sshloginmonitor.LogToEvents(logF, db, *bucketName)
	if err != nil {
		log.Fatal(err)
	}

	sessions := sshloginmonitor.EventsToSessions(&events)

	switch *outputFormat {
	case "sum":
		sshloginmonitor.PrintSummary(sessions, *colorFlag)
	case "log":
		sshloginmonitor.PrintLog(events, *colorFlag)
	case "csv":
		sshloginmonitor.PrintCSV(events)
	case "json":
		sshloginmonitor.PrintJSON(events)
	}
}
