package sshloginmonitor

import "fmt"

// PrintSummary takes a slice of Session objects and prints a summary of each session.
// For each session, the function prints the username, source IP, start time, end time,
// and duration of the session in the format "username\tsourceIP\tstartTime\tendTime\tduration".
// The start time and end time are formatted using the "2006-01-02 15:04:05" layout.
//
// Parameters:
//   - sessions ([]Session): slice of Session objects
//
// Returns:
//   - None
func PrintSummary(sessions []Session) {
	for _, session := range sessions {
		fmt.Printf("%s\t%s\t%s\t%s\t%s\n", session.Username, session.SourceIP,
			session.StartTime.Format("2006-01-02 15:04:05"),
			session.EndTime.Format("2006-01-02 15:04:05"),
			session.EndTime.Sub(session.StartTime))
	}
}

// PrintLog prints the given list of SessionEvent objects with the specified format.
//
// Parameters:
//   - events (List[SessionEvent]): The list of SessionEvent objects to be printed.
//
// Returns:
//   - None
func PrintLog(events []SessionEvent) {
	for _, event := range events {
		fmt.Printf("%s\t%s\t%s\t%s\n", event.Username, event.EventType, event.SourceIP,
			event.EventTime.Format("2006-01-02 15:04:05"))
	}
}

// PrintCSV prints the given list of SessionEvent objects with the CSV format.
//
// Parameters:
//   - events (List[SessionEvent]): The list of SessionEvent objects to be printed.
//
// Returns:
//   - None
func PrintCSV(events []SessionEvent) {
	for _, event := range events {
		fmt.Printf("%s,%s,%s,%s\n", event.Username, event.EventType, event.SourceIP,
			event.EventTime.Format("2006-01-02 15:04:05"))
	}
}
