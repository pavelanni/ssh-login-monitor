package sshloginmonitor

import (
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"
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
	type args struct {
		reader io.Reader
		users  *[]User
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
					`Apr 27 10:21:19 deep-rh sshd[1337250]: Accepted publickey for root from 192.168.1.24 port 49090 ssh2: ED25519 SHA256:fp1
Apr 27 10:21:19 deep-rh systemd[1337257]: pam_unix(systemd-user:session): session opened for user root by (uid=0)
Apr 27 10:21:19 deep-rh sshd[1337250]: pam_unix(sshd:session): session opened for user root by (uid=0)
Apr 27 10:21:22 deep-rh sshd[1337282]: Received disconnect from 192.168.1.24 port 49090:11: disconnected by user
Apr 27 10:21:22 deep-rh sshd[1337250]: pam_unix(sshd:session): session closed for user root
Apr 27 10:21:32 deep-rh systemd[1337261]: pam_unix(systemd-user:session): session closed for user root
Apr 27 10:21:34 deep-rh sshd[1337458]: Accepted publickey for root from 192.168.1.24 port 41254 ssh2: ED25519 SHA256:fp2
Apr 27 10:21:34 deep-rh systemd[1337467]: pam_unix(systemd-user:session): session opened for user root by (uid=0)
Apr 27 10:21:34 deep-rh sshd[1337458]: pam_unix(sshd:session): session opened for user root by (uid=0)
		`),
				users: &[]User{
					{
						Username:    "user1",
						Fingerprint: "fp1",
					},
					{
						Username:    "user2",
						Fingerprint: "fp2",
					},
				},
			},
			want: []SessionEvent{
				{
					EventTime: time1,
					EventType: "login",
					Username:  "user1",
					SourceIP:  "192.168.1.24",
					Port:      "49090",
				},
				{
					EventTime: time2,
					EventType: "login",
					Username:  "user2",
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
				users: &[]User{
					{
						Username:    "user1",
						Fingerprint: "fp1",
					},
					{
						Username:    "user2",
						Fingerprint: "fp2",
					},
				},
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
				users: &[]User{
					{
						Username:    "user1",
						Fingerprint: "fp1",
					},
					{
						Username:    "user2",
						Fingerprint: "fp2",
					},
				},
			},
			want:    nil,
			wantErr: errors.New("invalid event"),
		},
		{
			name: "invalid logout event",
			args: args{
				reader: strings.NewReader(
					`Apr 27 10:21:22 deep-rh sshd[1337282]: Disconnected from user root 192.168.1.24 port`),
				users: &[]User{
					{
						Username:    "user1",
						Fingerprint: "fp1",
					},
					{
						Username:    "user2",
						Fingerprint: "fp2",
					},
				},
			},
			want:    nil,
			wantErr: errors.New("invalid event"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := LogToEvents(tt.args.reader, tt.args.users)
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