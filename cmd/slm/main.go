package main

import (
	"fmt"
	"log"
	"os"

	"github.com/pavelanni/ssh-login-monitor/pkg/config"
	"github.com/pavelanni/ssh-login-monitor/pkg/sshloginmonitor"
	bolt "go.etcd.io/bbolt"
)

func main() {

	err := config.LoadKonfig("config/config.yaml")
	if err != nil {
		log.Fatal(err)
	}

	db, err := bolt.Open(config.K.String("database"), 0600, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(config.K.String("bucket")))
		if err != nil {
			return fmt.Errorf("create bucket: %s", err)
		}
		return nil
	})
	if err != nil {
		log.Fatal(err)
	}

	if config.K.String("authkeys") != "" {
		users := make([]sshloginmonitor.User, 0)

		f, err := os.Open(config.K.String("authkeys"))
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()

		err = sshloginmonitor.GetAuthKeys(f, &users)
		if err != nil {
			log.Fatal(err)
		}
		err = sshloginmonitor.AddUsersToDB(users, db, config.K.String("bucket"))
		if err != nil {
			log.Fatal(err)
		}
	}

	if config.K.String("log") == "" {
		fmt.Println("No log file specified. Exiting...")
		os.Exit(1)
	}

	logF, err := os.Open(config.K.String("log"))
	if err != nil {
		log.Fatal(err)
	}
	defer logF.Close()

	events, err := sshloginmonitor.LogToEvents(logF, db, config.K.String("bucket"))
	if err != nil {
		log.Fatal(err)
	}

	sessions := sshloginmonitor.EventsToSessions(&events)

	switch config.K.String("output") {
	case "sum":
		sshloginmonitor.PrintSummary(sessions, config.K.Bool("color"))
	case "log":
		sshloginmonitor.PrintLog(events, config.K.Bool("color"))
	case "csv":
		sshloginmonitor.PrintCSV(events)
	case "json":
		sshloginmonitor.PrintJSON(events)
	}
}
