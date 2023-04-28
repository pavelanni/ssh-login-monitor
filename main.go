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
	logFile := flag.StringP("log", "l", "secure.log", "Log file to parse")
	needHelp := flag.BoolP("help", "h", false, "This help message")
	flag.Parse()

	if *needHelp {
		flag.Usage()
		os.Exit(1)
	}
	users := make([]sshloginmonitor.User, 0)
	err := sshloginmonitor.GetUsers(*usersDB, &users)
	if err != nil {
		log.Fatal(err)
	}

	events, err := sshloginmonitor.LogToEvents(*logFile, &users)
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
