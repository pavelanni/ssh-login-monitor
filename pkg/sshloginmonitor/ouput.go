package sshloginmonitor

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/fatih/color"
	"github.com/pavelanni/ssh-login-monitor/pkg/config"
)

var colorMap = map[string]color.Attribute{
	"black":   color.FgBlack,
	"red":     color.FgRed,
	"green":   color.FgGreen,
	"blue":    color.FgBlue,
	"magenta": color.FgMagenta,
	"cyan":    color.FgCyan,
	"white":   color.FgWhite,
	"yellow":  color.FgYellow,
}

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
func PrintSummary(sessions []Session, colorFlag bool) {
	if !colorFlag {
		color.NoColor = true
	}
	usernameColor := color.New(colorMap[config.K.String("theme.username")]).SprintFunc()
	sourceipColor := color.New(colorMap[config.K.String("theme.sourceip")]).SprintFunc()
	starttimeColor := color.New(colorMap[config.K.String("theme.starttime")]).SprintFunc()
	endtimeColor := color.New(colorMap[config.K.String("theme.endtime")]).SprintFunc()
	for _, session := range sessions {
		fmt.Printf("%s\t%s\t%s\t%s\t%s\n", usernameColor(session.Username),
			sourceipColor(session.SourceIP),
			starttimeColor(session.StartTime.Format("2006-01-02 15:04:05")),
			endtimeColor(session.EndTime.Format("2006-01-02 15:04:05")),
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
func PrintLog(events []SessionEvent, colorFlag bool) {
	for _, event := range events {
		PrintEvent(event, colorFlag)
	}
}

func PrintEvent(event SessionEvent, colorFlag bool) {
	if !colorFlag {
		color.NoColor = true
	}
	usernameColor := color.New(colorMap[config.K.String("theme.username")]).SprintFunc()
	eventtypeColor := color.New(colorMap[config.K.String("theme.eventtype")]).SprintFunc()
	eventtimeColor := color.New(colorMap[config.K.String("theme.eventtime")]).SprintFunc()
	sourceipColor := color.New(colorMap[config.K.String("theme.sourceip")]).SprintFunc()
	fmt.Printf("%s\t%s\t%s\t%s\n", usernameColor(event.Username),
		eventtypeColor(event.EventType),
		sourceipColor(event.SourceIP),
		eventtimeColor(event.EventTime.Format("2006-01-02 15:04:05")))
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

// PrintJSON prints the given list of SessionEvent objects with the JSON format.
func PrintJSON(events []SessionEvent) {
	output, err := json.MarshalIndent(events, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(output))
}
