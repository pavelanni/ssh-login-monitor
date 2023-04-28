package sshloginmonitor

/*
createUserMap takes in a slice of User objects and returns a map with
the user's fingerprint as the key and the User object as the value.

Parameters:
  - users ([]User): a slice of User objects.

Returns:
  - (map[string]User): a map with the user's fingerprint as the key and the User object as the value.
*/
func createUserMap(users []User) map[string]User {
	userMap := make(map[string]User)
	for _, user := range users {
		userMap[user.Fingerprint] = user
	}
	return userMap
}
