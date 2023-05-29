package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/knadh/koanf/parsers/json"
	"github.com/knadh/koanf/providers/rawbytes"
	"github.com/pavelanni/ssh-login-monitor/pkg/config"
	"github.com/pavelanni/ssh-login-monitor/pkg/sshloginmonitor"
	bolt "go.etcd.io/bbolt"
)

func main() {

	err := config.LoadKonfig()
	if err != nil {
		log.Fatal(err)
	}
	// Open database file
	db, err := bolt.Open(config.K.String("database"), 0600, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Create bucket if it doesn't exist
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

	// Check if authkeys file is provided
	if config.K.String("authkeys") != "" {
		// Parse authkeys file and add users to the database
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

	var events []sshloginmonitor.SessionEvent
	var sessions []sshloginmonitor.Session

	if config.K.String("log") == "journal" {
		err := sshloginmonitor.JournalToEvents(db, config.K.String("bucket"))
		if err != nil {
			log.Fatal(err)
		}
	} else {
		logFile, err := os.Open(config.K.String("log"))
		if err != nil {
			log.Fatal(err)
		}
		defer logFile.Close()

		events, err = sshloginmonitor.LogToEvents(logFile, db, config.K.String("bucket"))
		if err != nil {
			log.Fatal(err)
		}

	}
	sessions = sshloginmonitor.EventsToSessions(&events)

	// Check if follow flag is set to true
	if config.K.Bool("follow") {
		// Update configuration to output log to console
		b := []byte(`{"output": "log"}`)
		err := config.K.Load(rawbytes.Provider(b), json.Parser())
		if err != nil {
			log.Fatal(err)
		}
	}
	// Switch output format based on configuration
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

	// Check if follow flag is set to true
	if config.K.Bool("follow") {
		if config.K.String("log") != "journal" {
			// done is the channel to notify the WatchLog function to stop watching and exit
			done := make(chan struct{})
			go func() {
				sigint := make(chan os.Signal, 1)
				signal.Notify(sigint, os.Interrupt)
				<-sigint
				close(done)
			}()

			// Watch log file for changes
			logFile, err := os.Open(config.K.String("log"))
			if err != nil {
				log.Fatal(err)
			}
			defer logFile.Close()
			err = sshloginmonitor.WatchLog(logFile, db, config.K.String("bucket"), &sessions, done)
			if err != nil {
				log.Fatal(err)
			}

		}
	}
}
