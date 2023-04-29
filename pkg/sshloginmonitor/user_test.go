package sshloginmonitor

import (
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
)

func TestGetUsers(t *testing.T) {
	type args struct {
		reader io.Reader
		users  *[]User
	}
	tests := []struct {
		name    string
		args    args
		want    *[]User
		wantErr error
	}{
		{
			name: "valid users and fingerprints",
			args: args{
				reader: strings.NewReader("user1,fingerprint1\nuser2,fingerprint2\n"),
				users:  &[]User{},
			},
			want:    &[]User{{Username: "user1", Fingerprint: "fingerprint1"}, {Username: "user2", Fingerprint: "fingerprint2"}},
			wantErr: nil,
		},
		{
			name: "empty file",
			args: args{
				reader: strings.NewReader(""),
				users:  &[]User{},
			},
			want:    &[]User{},
			wantErr: errors.New("no users in the file"),
		},
		{
			name: "missing fingerprint",
			args: args{
				reader: strings.NewReader("user1\nuser2\n"),
				users:  &[]User{},
			},
			want:    &[]User{},
			wantErr: errors.New("missing fingerprint"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := GetUsers(tt.args.reader, tt.args.users)
			if err != nil {
				if err.Error() != tt.wantErr.Error() {
					t.Errorf("GetUsers() error = %v, wantErr %v", err, tt.wantErr)
				}
			} else {
				if !reflect.DeepEqual(*tt.args.users, *tt.want) {
					t.Errorf("GetUsers() = %v, want %v", *tt.args.users, *tt.want)
				}
			}
		})
	}
}
