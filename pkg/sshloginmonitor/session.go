package sshloginmonitor

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"regexp"
	"time"

	bolt "go.etcd.io/bbolt"
)

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

// LogToEvents takes a filename string and a pointer to a slice of User structs.
// It returns a slice of SessionEvent structs and an error. This function reads
// a log file, parses each line, and creates SessionEvent structs based on the
// contents of each line. The SessionEvent structs are returned in a slice.
//
// Parameters:
//   - filename: string representing the path to the log file to be read
//
// users - pointer to a slice of User structs to be used when creating SessionEvent
// structs
//
// Returns:
//   - ([]SessionEvent): a slice of SessionEvent structs and an error, if it occurs
func LogToEvents(reader io.Reader, db *bolt.DB, bucket string) ([]SessionEvent, error) {
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

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		if reLogin.MatchString(line) {
			match := reParseLogin.FindStringSubmatch(line)
			if match == nil {
				log.Println("invalid event: " + line)
				continue
			}
			result := make(map[string]string)
			for i, name := range reParseLogin.SubexpNames() {
				if i != 0 {
					result[name] = match[i]
				}
			}
			eventTime, err := time.Parse("2006 Jan 02 15:04:05",
				fmt.Sprintf("%d ", time.Now().Year())+result["date"]+" "+result["time"])
			if err != nil {
				return nil, err
			}
			username, err := GetUserByFingerprint(result["fingerprint"], db, bucket)
			if err != nil {
				log.Println(err)
				continue
			}
			if username == "" {
				log.Println("username not found in line " + line)
				continue
			}
			event := SessionEvent{
				EventType: "login",
				EventTime: eventTime,
				Username:  username,
				SourceIP:  result["loginIP"],
				Port:      result["port"],
			}
			events = append(events, event)
		}
		if reLogout.MatchString(line) {
			match := reParseLogout.FindStringSubmatch(line)
			if match == nil {
				log.Println("invalid event: " + line)
				continue
			}
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

// EventsToSessions converts a slice of SessionEvent into a slice of Session.
// It maintains a mapping of port to the user that logged in using that port,
// and uses this mapping to pair logout events with their corresponding login events.
//
// Parameters:
//   - events: The slice of SessionEvent to be converted to Session.
//
// Returns:
//   - sessions: A slice of Session representing the sessions created by the given events.
func EventsToSessions(events *[]SessionEvent) []Session {
	sessions := []Session{}
	portToUser := make(map[string]string)

	for j, event := range *events {
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
				// update the user in the logout event
				(*events)[j].Username = user
				// find the session with the same port in sessions
				for i, session := range sessions {
					if session.Username == user && session.SourceIP == event.SourceIP && session.Port == port {
						session.EndTime = event.EventTime
						sessions[i] = session
						delete(portToUser, port)
					}
				}
			} else {
				log.Printf("login event for port %s not found\n", port)
			}
		}
	}
	return sessions
}
