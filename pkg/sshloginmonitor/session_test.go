package sshloginmonitor

import (
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func TestLogToEvents(t *testing.T) {
	time1, err := time.Parse("2006 Jan 02 15:04:05", fmt.Sprintf("%d ", time.Now().Year())+"Apr 27 10:21:19")
	if err != nil {
		t.Fatal(err)
	}
	time2, err := time.Parse("2006 Jan 02 15:04:05", fmt.Sprintf("%d ", time.Now().Year())+"Apr 27 10:21:34")
	if err != nil {
		t.Fatal(err)
	}
	time3, err := time.Parse("2006 Jan 02 15:04:05", fmt.Sprintf("%d ", time.Now().Year())+"Apr 27 10:21:22")
	if err != nil {
		t.Fatal(err)
	}
	time4, err := time.Parse("2006 Jan 02 15:04:05", fmt.Sprintf("%d ", time.Now().Year())+"Apr 27 10:21:37")
	if err != nil {
		t.Fatal(err)
	}

	db, err := bolt.Open("/home/pavel/Projects/ssh-login-monitor/fingerprints.db", 0600, nil)
	if err != nil {
		panic(err)
	}
	bucket := "LoginMonitor"
	defer db.Close()

	type args struct {
		reader io.Reader
		db     *bolt.DB
		bucket string
	}
	tests := []struct {
		name    string
		args    args
		want    []SessionEvent
		wantErr error
	}{
		{
			name: "valid login events",
			args: args{
				reader: strings.NewReader(
					`Apr 27 10:21:19 deep-rh sshd[1337250]: Accepted publickey for root from 192.168.1.24 port 49090 ssh2: ED25519 SHA256:5xuxPx8QnPv19/6IZ5frmQj1N0hRCP9J364ddE6avL8
Apr 27 10:21:19 deep-rh systemd[1337257]: pam_unix(systemd-user:session): session opened for user root by (uid=0)
Apr 27 10:21:19 deep-rh sshd[1337250]: pam_unix(sshd:session): session opened for user root by (uid=0)
Apr 27 10:21:22 deep-rh sshd[1337282]: Received disconnect from 192.168.1.24 port 49090:11: disconnected by user
Apr 27 10:21:22 deep-rh sshd[1337250]: pam_unix(sshd:session): session closed for user root
Apr 27 10:21:32 deep-rh systemd[1337261]: pam_unix(systemd-user:session): session closed for user root
Apr 27 10:21:34 deep-rh sshd[1337458]: Accepted publickey for root from 192.168.1.24 port 41254 ssh2: ED25519 SHA256:is6l6bRqCCBVKunT+zVGHoUF0A06p8lt/04EoRbyCUY
Apr 27 10:21:34 deep-rh systemd[1337467]: pam_unix(systemd-user:session): session opened for user root by (uid=0)
Apr 27 10:21:34 deep-rh sshd[1337458]: pam_unix(sshd:session): session opened for user root by (uid=0)
		`),
				db:     db,
				bucket: bucket,
			},
			want: []SessionEvent{
				{
					EventTime: time1,
					EventType: "login",
					Username:  "alice@fedora",
					SourceIP:  "192.168.1.24",
					Port:      "49090",
				},
				{
					EventTime: time2,
					EventType: "login",
					Username:  "bob@fedora",
					SourceIP:  "192.168.1.24",
					Port:      "41254",
				},
			},
			wantErr: nil,
		},
		{
			name: "valid logout events",
			args: args{
				reader: strings.NewReader(
					`Apr 27 10:21:22 deep-rh sshd[1337282]: Received disconnect from 192.168.1.24 port 49090:11: disconnected by user
Apr 27 10:21:22 deep-rh sshd[1337282]: Disconnected from user root 192.168.1.24 port 49090
Apr 27 10:21:22 deep-rh sshd[1337250]: pam_unix(sshd:session): session closed for user root
Apr 27 10:21:32 deep-rh systemd[1337261]: pam_unix(systemd-user:session): session closed for user root
Apr 27 10:21:34 deep-rh systemd[1337467]: pam_unix(systemd-user:session): session opened for user root by (uid=0)
Apr 27 10:21:34 deep-rh sshd[1337458]: pam_unix(sshd:session): session opened for user root by (uid=0)
Apr 27 10:21:37 deep-rh sshd[1337493]: Received disconnect from 192.168.1.24 port 41254:11: disconnected by user
Apr 27 10:21:37 deep-rh sshd[1337493]: Disconnected from user root 192.168.1.24 port 41254
Apr 27 10:21:37 deep-rh sshd[1337458]: pam_unix(sshd:session): session closed for user root
`),
				db:     db,
				bucket: bucket,
			},
			want: []SessionEvent{
				{
					EventTime: time3,
					EventType: "logout",
					Username:  "root",
					SourceIP:  "192.168.1.24",
					Port:      "49090",
				},
				{
					EventTime: time4,
					EventType: "logout",
					Username:  "root",
					SourceIP:  "192.168.1.24",
					Port:      "41254",
				},
			},
			wantErr: nil,
		},
		{
			name: "invalid login event",
			args: args{
				reader: strings.NewReader(
					`Apr 27 10:21:19 deep-rh sshd[1337250]: Accepted publickey for root from 192.168.1.24 port 49090 ssh2: ED25519 SH`),
				db:     db,
				bucket: bucket,
			},
			want:    []SessionEvent{},
			wantErr: errors.New("invalid event"),
		},
		{
			name: "invalid logout event",
			args: args{
				reader: strings.NewReader(
					`Apr 27 10:21:22 deep-rh sshd[1337282]: Disconnected from user root 192.168.1.24 port`),
				db:     db,
				bucket: bucket,
			},
			want:    []SessionEvent{},
			wantErr: errors.New("invalid event"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := LogToEvents(tt.args.reader, tt.args.db, tt.args.bucket)
			if err != nil {
				if err.Error() != tt.wantErr.Error() {
					t.Errorf("LogToEvents() error = %v, wantErr %v", err, tt.wantErr)
				}
			} else {
				if !reflect.DeepEqual(got, tt.want) {
					t.Errorf("LogToEvents() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestEventsToSessions(t *testing.T) {
	type args struct {
		events []SessionEvent
	}
	tests := []struct {
		name string
		args args
		want []Session
	}{
		{
			name: "valid events to sessions",
			args: args{
				events: []SessionEvent{
					{
						EventType: "login",
						EventTime: time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
						Username:  "user1",
						SourceIP:  "192.168.1.24",
						Port:      "49090",
					},
					{
						EventType: "logout",
						EventTime: time.Date(2023, 1, 1, 0, 1, 0, 0, time.UTC),
						Username:  "user1",
						SourceIP:  "192.168.1.24",
						Port:      "49090",
					},
				},
			},
			want: []Session{
				{
					Username:  "user1",
					SourceIP:  "192.168.1.24",
					Port:      "49090",
					StartTime: time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
					EndTime:   time.Date(2023, 1, 1, 0, 1, 0, 0, time.UTC),
				},
			},
		},
		// Need more tests for different combinations of events.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := EventsToSessions(tt.args.events); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("EventsToSessions() = %v, want %v", got, tt.want)
			}
		})
	}
}
