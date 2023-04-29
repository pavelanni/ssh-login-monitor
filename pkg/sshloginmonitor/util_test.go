package sshloginmonitor

import (
	"errors"
	"reflect"
	"testing"
)

func Test_createUserMap(t *testing.T) {
	type args struct {
		users []User
	}
	tests := []struct {
		name    string
		args    args
		want    map[string]User
		wantErr error
	}{
		{
			name: "valid users and fingerprints",
			args: args{
				users: []User{
					{
						Username:    "alice",
						Fingerprint: "AAAAAA==",
					},
					{
						Username:    "bob",
						Fingerprint: "BBBBBB==",
					},
					{
						Username:    "charlie",
						Fingerprint: "CCCCCC==",
					},
				},
			},
			want: map[string]User{
				"AAAAAA==": {
					Username:    "alice",
					Fingerprint: "AAAAAA==",
				},
				"BBBBBB==": {
					Username:    "bob",
					Fingerprint: "BBBBBB==",
				},
				"CCCCCC==": {
					Username:    "charlie",
					Fingerprint: "CCCCCC==",
				},
			},
			wantErr: nil,
		},
		{
			name: "duplicate fingerprints",
			args: args{
				users: []User{
					{
						Username:    "alice",
						Fingerprint: "AAAAAA==",
					},
					{
						Username:    "bob",
						Fingerprint: "AAAAAA==",
					},
				},
			},
			want:    nil,
			wantErr: errors.New("duplicate fingerprint"),
		},
		{
			name: "empty users",
			args: args{
				users: []User{},
			},
			want:    nil,
			wantErr: errors.New("no users"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := createUserMap(tt.args.users)
			if err != nil {
				if err.Error() != tt.wantErr.Error() {
					t.Errorf("createUserMap() error = %v, wantErr %v", err, tt.wantErr)
				}
			} else {
				if !reflect.DeepEqual(got, tt.want) {
					t.Errorf("createUserMap() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}
