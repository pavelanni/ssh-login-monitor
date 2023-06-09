package sshloginmonitor

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"time"

	"github.com/coreos/go-systemd/sdjournal"
	"github.com/fsnotify/fsnotify"
	"github.com/pavelanni/ssh-login-monitor/pkg/config"
	"github.com/rs/zerolog"
	bolt "go.etcd.io/bbolt"
)

type SessionEvent struct {
	EventType string    `json:"event_type"`
	EventTime time.Time `json:"event_time"`
	Username  string    `json:"username"`
	SourceIP  string    `json:"source_ip"`
	Port      string    `json:"port"`
	KeyUser   string    `json:"key_user"`
}

type Session struct {
	Username  string    `json:"username"`
	SourceIP  string    `json:"source_ip"`
	Port      string    `json:"port"`
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
	KeyUser   string    `json:"key_user"`
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

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		event, err := getLogEvent(line, db, bucket)
		if err != nil {
			return nil, err
		}
		if event == (SessionEvent{}) {
			continue
		}
		events = append(events, event)
	}
	return events, nil
}

func JournalToEvents(ctx context.Context, db *bolt.DB, bucket string) error {
	sessions := &[]Session{}
	portToUser := make(map[string]string)

	//logger := zerolog.New(os.Stderr).With().Logger()
	consoleLogger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, NoColor: false})

	j, err := sdjournal.NewJournal()
	if err != nil {
		return err
	}
	defer j.Close()

	// Match by SYSLOG_IDENTIFIER
	err = j.AddMatch("SYSLOG_IDENTIFIER=sshd")
	if err != nil {
		return err
	}

	// Start at the beginning of the journal
	err = j.SeekHead()
	if err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			n, err := j.Next()
			if err != nil {
				log.Println(err)
				break
			}
			if n == 0 {
				// No new entries, wait for new ones if "follow" is set
				if config.K.Bool("follow") {
					j.Wait(sdjournal.IndefiniteWait)
					continue
				} else {
					return nil
				}
			}
			entry, err := j.GetEntry()
			if err != nil {
				return err
			}
			if _, ok := entry.Fields["MESSAGE"]; ok {
				line := fmt.Sprintf("%s %s %s[%s]: %s", // reproduce format of journalctl output; should be refactored
					entry.Fields["SYSLOG_TIMESTAMP"],
					entry.Fields["_HOSTNAME"],
					entry.Fields["SYSLOG_IDENTIFIER"],
					entry.Fields["_PID"],
					entry.Fields["MESSAGE"],
				)
				event, err := getLogEvent(line, db, bucket)
				if err != nil {
					return err
				}
				if event == (SessionEvent{}) {
					continue
				}
				event, err = processEvent(event, sessions, portToUser)
				if err != nil {
					return err
				}
				consoleLogger.Info().
					Str("event time", event.EventTime.String()).
					Str("event type", event.EventType).
					Str("username", event.Username).
					Str("source ip", event.SourceIP).
					Str("port", event.Port).
					Str("key user", event.KeyUser).
					Msg("ssh event")
				// PrintEvent(event, config.K.Bool("color"))
			}
		}
	}
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

	for i, event := range *events {
		eventUpdated, err := processEvent(event, &sessions, portToUser)
		if err != nil {
			log.Println(err)
			continue
		}
		(*events)[i] = eventUpdated
	}
	return sessions
}

// WatchLog watches the logFile for login events and logs them to the output.
func WatchLog(ctx context.Context, input *os.File, db *bolt.DB, bucket string, sessions *[]Session) error {
	portToUser := make(map[string]string)

	var offset int64
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer watcher.Close()

	err = watcher.Add(input.Name())
	if err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case event := <-watcher.Events:
			if event.Op&fsnotify.Write == fsnotify.Write {
				_, err := input.Seek(offset, io.SeekStart)
				if err != nil {
					return err
				}
				scanner := bufio.NewScanner(input)

				for scanner.Scan() {
					line := scanner.Text()
					logEvent, err := getLogEvent(line, db, bucket)
					if err != nil {
						return err
					}

					if (logEvent == SessionEvent{}) {
						continue
					}
					logEvent, err = processEvent(logEvent, sessions, portToUser)
					if err != nil {
						log.Println(err)
					}
					PrintEvent(logEvent, config.K.Bool("color"))
					offset, _ = input.Seek(0, io.SeekCurrent)
				}
			}
		case err := <-watcher.Errors:
			return err
		}
	}
}

func getLogEvent(line string, db *bolt.DB, bucket string) (SessionEvent, error) {
	// regexp for login pattern
	reLogin := regexp.MustCompile(`Accepted publickey for `)
	// regexp for logout pattern
	reLogout := regexp.MustCompile(`Disconnected from user `)
	reParseLogin := regexp.MustCompile(`(?P<date>[A-Z][a-z]{2} [0-9]{2}) (?P<time>[0-9]{2}:[0-9]{2}:[0-9]{2})` +
		`.*Accepted publickey for (?P<username>[a-zA-Z0-9_]*) from (?P<loginIP>[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}) ` +
		`port (?P<port>[0-9]{1,6})` +
		`.* SHA256:(?P<fingerprint>[a-zA-Z0-9+\/]*$)`)
	reParseLogout := regexp.MustCompile(`(?P<date>[A-Z][a-z]{2} [0-9]{2}) (?P<time>[0-9]{2}:[0-9]{2}:[0-9]{2})` +
		`.*Disconnected from user (?P<username>[a-zA-Z0-9_]*) (?P<loginIP>[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}) ` +
		`port (?P<port>[0-9]{1,6})`)

	event := SessionEvent{}

	if reLogin.MatchString(line) {
		match := reParseLogin.FindStringSubmatch(line)
		if match == nil {
			return SessionEvent{}, nil
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
			return SessionEvent{}, err
		}
		keyUser, err := GetUserByFingerprint(result["fingerprint"], db, bucket)
		if err != nil {
			return SessionEvent{}, err
		}
		if keyUser == "" {
			log.Println("key user not found in line " + line)
		}
		event = SessionEvent{
			EventType: "login",
			EventTime: eventTime,
			Username:  result["username"],
			SourceIP:  result["loginIP"],
			Port:      result["port"],
			KeyUser:   keyUser,
		}
	}
	if reLogout.MatchString(line) {
		match := reParseLogout.FindStringSubmatch(line)
		if match == nil {
			return SessionEvent{}, nil
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
			return SessionEvent{}, err
		}
		event = SessionEvent{
			EventType: "logout",
			EventTime: eventTime,
			Username:  result["username"],
			KeyUser:   "????",
			SourceIP:  result["loginIP"],
			Port:      result["port"],
		}
	}
	return event, nil
}

// processEvent updated []sessions and returns the updated event
// where user is replaced with the actual user based on the sessions database
func processEvent(event SessionEvent, sessions *[]Session, portToUser map[string]string) (SessionEvent, error) {
	if event.EventType == "login" {
		portToUser[event.Port] = event.KeyUser
		session := Session{
			Username:  event.Username,
			Port:      event.Port,
			SourceIP:  event.SourceIP,
			StartTime: event.EventTime,
			KeyUser:   event.KeyUser,
		}
		*sessions = append(*sessions, session)
		return event, nil
	} else if event.EventType == "logout" {
		port := event.Port
		if user, ok := portToUser[port]; ok {
			// update the user in the logout event
			event.KeyUser = user
			// find the session with the same port in sessions
			for i, session := range *sessions {
				if session.KeyUser == user && session.SourceIP == event.SourceIP && session.Port == port {
					session.EndTime = event.EventTime
					(*sessions)[i] = session
					delete(portToUser, port)
				}
			}
			return event, nil
		} else {
			log.Printf("login event for port %s not found\n", port)
			return event, nil
		}
	}
	return event, nil
}
