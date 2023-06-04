package sshloginmonitor

import (
	"io"
	"reflect"
	"strings"
	"testing"
)

func TestGetAuthKeys(t *testing.T) {
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
			name: "empty authorized keys file",
			args: args{
				reader: strings.NewReader(""),
				users:  &[]User{},
			},
			want:    &[]User{},
			wantErr: nil,
		},
		{
			name: "valid authorized keys file",
			args: args{
				reader: strings.NewReader(`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG8Obx1FsUu1jlYDtzfEDHYSDjG82xE7ysxZVzhgpGC5 alice@fedora
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJgclT4eQ5RlYabZfkdjFV5wGrroXxmd5n2X7okmiaN8 bob@fedora
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJWcjljox2NKwDFllZ5KQc4LSVrBEKoaOE/t/up1XbyD charlie@fedora`),
				users: &[]User{},
			},
			want: &[]User{
				{Username: "alice@fedora", Fingerprint: "5xuxPx8QnPv19/6IZ5frmQj1N0hRCP9J364ddE6avL8"},
				{Username: "bob@fedora", Fingerprint: "is6l6bRqCCBVKunT+zVGHoUF0A06p8lt/04EoRbyCUY"},
				{Username: "charlie@fedora", Fingerprint: "QgAov0UZI25hWxnbLiHa00j64/zD1m80UMsSIZtxr2s"},
			},
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := getAuthKeys(tt.args.reader, tt.args.users)
			if err != nil {
				if err.Error() != tt.wantErr.Error() {
					t.Errorf("GetAuthKeys() error = %v, wantErr %v", err, tt.wantErr)
				}
			} else {
				if !reflect.DeepEqual(tt.args.users, tt.want) {
					t.Errorf("GetAuthKeys() = %v, want %v", tt.args.users, tt.want)
				}
			}
		})
	}
}
