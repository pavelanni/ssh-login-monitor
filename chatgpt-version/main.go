package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Println("Usage: go run main.go <log_file> <authorized_keys_file>")
		os.Exit(1)
	}

	logFile := os.Args[1]
	authKeysFile := os.Args[2]

	keys, err := readAuthKeys(authKeysFile)
	if err != nil {
		fmt.Printf("Error reading authorized_keys file: %v\n", err)
		os.Exit(1)
	}

	events, err := readLog(logFile, keys)
	if err != nil {
		fmt.Printf("Error reading log file: %v\n", err)
		os.Exit(1)
	}

	for _, event := range events {
		fmt.Println(event)
	}
}

type AuthKey struct {
	User        string
	Fingerprint string
}

type Event struct {
	User      string
	Time      time.Time
	IP        string
	Port      string
	EventType string
}

func readAuthKeys(filename string) (map[string]AuthKey, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	keys := make(map[string]AuthKey)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, " ")
		user := strings.Split(parts[2], "@")[0]

		pubKey := parts[1]
		fingerprint := calcFingerprint(pubKey)
		keys[fingerprint] = AuthKey{User: user, Fingerprint: fingerprint}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return keys, nil
}

func calcFingerprint(pubKey string) string {
	data, _ := base64.StdEncoding.DecodeString(pubKey)
	h := sha256.New()
	h.Write(data)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(h.Sum(nil))
}

func readLog(filename string, authKeys map[string]AuthKey) ([]Event, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var events []Event
	scanner := bufio.NewScanner(file)
	loginRe := regexp.MustCompile(`Accepted publickey for root from ([\d.]+) port (\d+) ssh2: ED25519 (SHA256:[^ ]+)`)
	logoutRe := regexp.MustCompile(`Disconnected from user root ([\d.]+) port (\d+)`)

	for scanner.Scan() {
		line := scanner.Text()
		if loginMatch := loginRe.FindStringSubmatch(line); loginMatch != nil {
			timestamp, _ := time.Parse("Jan _2 15:04:05", line[:15])
			key := loginMatch[3]
			event := Event{
				User:      authKeys[key].User,
				Time:      timestamp,
				IP:        loginMatch[1],
				Port:      loginMatch[2],
				EventType: "Login",
			}
			events = append(events, event)
		} else if logoutMatch := logoutRe.FindStringSubmatch(line); logoutMatch != nil {
			timestamp, _ := time.Parse("Jan _2 15:04:05", line[:15])
			event := Event{
				User:      "",
				Time:      timestamp,
				IP:        logoutMatch[1],
				Port:      logoutMatch[2],
				EventType: "Logout",
			}
			for _, loginEvent := range events {
				if loginEvent.EventType == "Login" && loginEvent.Port == event.Port && loginEvent.User != "" {
					event.User = loginEvent.User
					break
				}
			}
			events = append(events, event)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return events, nil
}

func (e Event) String() string {
	return fmt.Sprintf("%s: %s - %s - %s:%s", e.EventType, e.User, e.Time.Format("2006-01-02 15:04:05"), e.IP, e.Port)
}
