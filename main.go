package main

import (
	"fmt"
	"log"
	"os"

	"github.com/pavelanni/ssh-login-monitor/pkg/sshloginmonitor"
	flag "github.com/spf13/pflag"
)

func main() {
	usersDB := flag.StringP("users", "u", "users.csv", "CSV file with users fingerprints")
	authKeys := flag.StringP("authkeys", "a", "", "authorized_keys file containing public keys")
	logFile := flag.StringP("log", "l", "secure.log", "Log file to parse")
	needHelp := flag.BoolP("help", "h", false, "This help message")
	flag.Parse()

	if *needHelp {
		flag.Usage()
		os.Exit(1)
	}
	users := make([]sshloginmonitor.User, 0)
	f, err := os.Open(*usersDB)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	err = sshloginmonitor.GetUsers(f, &users)
	if err != nil {
		log.Fatal(err)
	}

	if *authKeys != "" {
		f, err = os.Open(*authKeys)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()

		err = sshloginmonitor.GetAuthKeys(f, &users)
		if err != nil {
			log.Fatal(err)
		}
	}

	logF, err := os.Open(*logFile)
	if err != nil {
		log.Fatal(err)
	}
	defer logF.Close()

	events, err := sshloginmonitor.LogToEvents(logF, &users)
	if err != nil {
		log.Fatal(err)
	}

	sessions := sshloginmonitor.EventsToSessions(events)

	for _, session := range sessions {
		fmt.Printf("%s\t%s\t%s\t%s\t%s\n", session.Username, session.SourceIP,
			session.StartTime.Format("2006-01-02 15:04:05"),
			session.EndTime.Format("2006-01-02 15:04:05"),
			session.EndTime.Sub(session.StartTime))
	}
}
