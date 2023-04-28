package main

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"regexp"
	"time"

	flag "github.com/spf13/pflag"
)

type User struct {
	Username    string
	Fingerprint string
}

type SessionEvent struct {
	EventType string
	EventTime time.Time
	Username  string
	SourceIP  string
	Port      string
}

type Session struct {
	Username  string
	SourceIP  string
	Port      string
	StartTime time.Time
	EndTime   time.Time
}

/*
getUsers reads a CSV file specified by filename and appends each record to the
slice pointed to by users. The CSV file is expected to have two fields per
record: a username and a fingerprint. If the file cannot be opened, or if there
is an error reading the file, an error is returned.

Parameters:
  - filename (string): the path to the CSV file to read
  - users (*[]User): a pointer to a slice of User structs to append to

Returns:
  - error: an error if one occurred, or nil if successful
*/
func getUsers(filename string, users *[]User) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	csvReader := csv.NewReader(f)
	records, err := csvReader.ReadAll()
	if err != nil {
		return err
	}

	for _, record := range records {
		user := User{
			Username:    record[0],
			Fingerprint: record[1],
		}
		*users = append(*users, user)
	}
	return nil

}

/*
createUserMap takes in a slice of User objects and returns a map with
the user's fingerprint as the key and the User object as the value.

Parameters:
  - users ([]User): a slice of User objects.

Returns:
  - (map[string]User): a map with the user's fingerprint as the key and the User object as the value.
*/
func createUserMap(users []User) map[string]User {
	userMap := make(map[string]User)
	for _, user := range users {
		userMap[user.Fingerprint] = user
	}
	return userMap
}

/*
logToEvents takes a filename string and a pointer to a slice of User structs.
It returns a slice of SessionEvent structs and an error. This function reads
a log file, parses each line, and creates SessionEvent structs based on the
contents of each line. The SessionEvent structs are returned in a slice.

Parameters:
  - filename: string representing the path to the log file to be read

users - pointer to a slice of User structs to be used when creating SessionEvent
structs

Returns:
  - ([]SessionEvent): a slice of SessionEvent structs and an error, if it occurs
*/
func logToEvents(filename string, users *[]User) ([]SessionEvent, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	uMap := createUserMap(*users)
	events := make([]SessionEvent, 0)

	// regexp for login pattern
	reLogin := regexp.MustCompile(`Accepted publickey for root`)
	// regexp for logout pattern
	reLogout := regexp.MustCompile(`Disconnected from user root`)
	reParseLogin := regexp.MustCompile(`(?P<date>[A-Z][a-z]{2} [0-9]{2}) (?P<time>[0-9]{2}:[0-9]{2}:[0-9]{2})` +
		`.* (?P<loginIP>[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}) ` +
		`port (?P<port>[0-9]{1,6})` +
		`.* SHA256:(?P<fingerprint>[a-zA-Z0-9+\/]*$)`)
	reParseLogout := regexp.MustCompile(`(?P<date>[A-Z][a-z]{2} [0-9]{2}) (?P<time>[0-9]{2}:[0-9]{2}:[0-9]{2})` +
		`.* (?P<loginIP>[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}) ` +
		`port (?P<port>[0-9]{1,6})`)

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		if reLogin.MatchString(line) {
			match := reParseLogin.FindStringSubmatch(line)
			result := make(map[string]string)
			for i, name := range reParseLogin.SubexpNames() {
				if i != 0 {
					result[name] = match[i]
				}
			}
			d := result["date"]
			t := result["time"]
			eventTime, err := time.Parse("2006 Jan 02 15:04:05", fmt.Sprintf("%d ", time.Now().Year())+d+" "+t)
			if err != nil {
				return nil, err
			}
			event := SessionEvent{
				EventType: "login",
				EventTime: eventTime,
				Username:  uMap[result["fingerprint"]].Username,
				SourceIP:  result["loginIP"],
				Port:      result["port"],
			}
			events = append(events, event)
		}
		if reLogout.MatchString(line) {
			match := reParseLogout.FindStringSubmatch(line)
			result := make(map[string]string)
			for i, name := range reParseLogout.SubexpNames() {
				if i != 0 {
					result[name] = match[i]
				}
			}
			d := result["date"]
			t := result["time"]
			eventTime, err := time.Parse("2006 Jan 02 15:04:05", fmt.Sprintf("%d ", time.Now().Year())+d+" "+t)
			if err != nil {
				return nil, err
			}
			event := SessionEvent{
				EventType: "logout",
				EventTime: eventTime,
				Username:  "root",
				SourceIP:  result["loginIP"],
				Port:      result["port"],
			}
			events = append(events, event)
		}
	}
	return events, nil
}

/*
eventsToSessions converts a slice of SessionEvent into a slice of Session.
It maintains a mapping of port to the user that logged in using that port,
and uses this mapping to pair logout events with their corresponding login events.

Parameters:
  - events: The slice of SessionEvent to be converted to Session.

Returns:
  - sessions: A slice of Session representing the sessions created by the given events.
*/
func eventsToSessions(events []SessionEvent) []Session {
	sessions := []Session{}
	portToUser := make(map[string]string)

	for _, event := range events {
		if event.EventType == "login" {
			portToUser[event.Port] = event.Username
			session := Session{
				Username:  event.Username,
				Port:      event.Port,
				SourceIP:  event.SourceIP,
				StartTime: event.EventTime,
			}
			sessions = append(sessions, session)
		} else if event.EventType == "logout" {
			port := event.Port
			if user, ok := portToUser[port]; ok {
				// find the session with the same port in sessions
				for i, session := range sessions {
					if session.Username == user && session.SourceIP == event.SourceIP && session.Port == port {
						session.EndTime = event.EventTime
						sessions[i] = session
						delete(portToUser, port)
					}
				}
			} else {
				log.Printf("%s port not found", port)
			}
		}
	}
	return sessions
}

func main() {
	usersDB := flag.StringP("users", "u", "users.csv", "CSV file with users fingerprints")
	logFile := flag.StringP("log", "l", "secure.log", "Log file to parse")
	needHelp := flag.BoolP("help", "h", false, "This help message")
	flag.Parse()

	if *needHelp {
		flag.Usage()
		os.Exit(1)
	}
	users := make([]User, 0)
	err := getUsers(*usersDB, &users)
	if err != nil {
		log.Fatal(err)
	}

	events, err := logToEvents(*logFile, &users)
	if err != nil {
		log.Fatal(err)
	}

	sessions := eventsToSessions(events)

	for _, session := range sessions {
		fmt.Printf("%s\t%s\t%s\t%s\t%s\n", session.Username, session.SourceIP,
			session.StartTime.Format("2006-01-02 15:04:05"),
			session.EndTime.Format("2006-01-02 15:04:05"),
			session.EndTime.Sub(session.StartTime))
	}
}
