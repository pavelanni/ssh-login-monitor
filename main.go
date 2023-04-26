package main

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"regexp"
	"time"
)

type User struct {
	Username    string
	Fingerprint string
	PublicKey   string
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
			PublicKey:   record[2],
		}
		*users = append(*users, user)
	}
	return nil

}

// Create a user map with fingerprint as key and username as value
func createUserMap(users []User) map[string]User {
	userMap := make(map[string]User)
	for _, user := range users {
		userMap[user.Fingerprint] = user
	}
	return userMap
}

// Read the log file and find root login and logout events using patterns
// login_pattern: "Accepted publickey for root"
// logout_pattern: "Disconnected from user root"
func logToEvents(filename string, users *[]User) ([]SessionEvent, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	uMap := createUserMap(*users)
	events := make([]SessionEvent, 0)

	// regexp for login_pattern
	reLogin := regexp.MustCompile(`Accepted publickey for root`)
	// regexp for logout_pattern
	reLogout := regexp.MustCompile(`Disconnected from user root`)
	reParseLogin := regexp.MustCompile(`(?P<date>[A-Z][a-z]{2} [0-9]{2}) (?P<time>[0-9]{2}:[0-9]{2}:[0-9]{2})` +
		`.* (?P<loginIP>[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}) ` +
		`port (?P<port>[0-9]{1,6})` +
		`.* SHA256:(?P<fingerprint>[a-zA-Z0-9+\/]*$)`)
	reParseLogout := regexp.MustCompile(`(?P<date>[A-Z][a-z]{2} [0-9]{2}) (?P<time>[0-9]{2}:[0-9]{2}:[0-9]{2})` +
		`.* (?P<loginIP>[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}) ` +
		`port (?P<port>[0-9]{1,6})`)

	scanner := bufio.NewScanner(f)
	//	var events []SessionEvent
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

func eventsToSessions(events []SessionEvent) []Session {
	sessions := make([]Session, 0)
	portUsers := make(map[string]string)

	for _, event := range events {
		if event.EventType == "login" {
			portUsers[event.Port] = event.Username
			session := Session{
				Username:  event.Username,
				Port:      event.Port,
				SourceIP:  event.SourceIP,
				StartTime: event.EventTime,
			}
			sessions = append(sessions, session)
		} else if event.EventType == "logout" {
			fmt.Println(event)
			port := event.Port
			if user, ok := portUsers[port]; ok {
				fmt.Println(port, user)
				// find the event with the same port in sessions
				for i, session := range sessions {
					if session.Username == user && session.SourceIP == event.SourceIP && session.Port == port {
						session.EndTime = event.EventTime
						sessions[i] = session
						delete(portUsers, port)
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
	users := make([]User, 0)
	err := getUsers("users.csv", &users)
	if err != nil {
		log.Fatal(err)
	}

	events, err := logToEvents("secure.log", &users)
	if err != nil {
		log.Fatal(err)
	}

	sessions := eventsToSessions(events)
	fmt.Println(sessions)

	for _, session := range sessions {
		fmt.Printf("%s\t%s\t%s\t%s\t%s\n", session.Username, session.SourceIP,
			session.StartTime.Format("2006-01-02 15:04:05"),
			session.EndTime.Format("2006-01-02 15:04:05"),
			session.EndTime.Sub(session.StartTime))
	}
}
