package sshloginmonitor

import (
	"encoding/csv"
	"os"
)

type User struct {
	Username    string
	Fingerprint string
}

/*
GetUsers reads a CSV file specified by filename and appends each record to the
slice pointed to by users. The CSV file is expected to have two fields per
record: a username and a fingerprint. If the file cannot be opened, or if there
is an error reading the file, an error is returned.

Parameters:
  - filename (string): the path to the CSV file to read
  - users (*[]User): a pointer to a slice of User structs to append to

Returns:
  - error: an error if one occurred, or nil if successful
*/
func GetUsers(filename string, users *[]User) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	csvReader := csv.NewReader(f)
	records, err := csvReader.ReadAll()
	if err != nil {
		return err
	}

	for _, record := range records {
		user := User{
			Username:    record[0],
			Fingerprint: record[1],
		}
		*users = append(*users, user)
	}
	return nil

}
