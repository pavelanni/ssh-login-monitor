package sshloginmonitor

import (
	"errors"
)

// createUserMap takes in a slice of User objects and returns a map with
// the user's fingerprint as the key and the User object as the value.
//
// Parameters:
//   - users ([]User): a slice of User objects.
//
// Returns:
//   - (map[string]User): a map with the user's fingerprint as the key and the User object as the value.
func createUserMap(users []User) (map[string]User, error) {
	if len(users) == 0 {
		return nil, errors.New("no users")
	}
	userMap := make(map[string]User)
	for _, user := range users {
		if _, ok := userMap[user.Fingerprint]; !ok {
			userMap[user.Fingerprint] = user
		} else {
			return nil, errors.New("duplicate fingerprint")
		}
	}
	return userMap, nil
}
