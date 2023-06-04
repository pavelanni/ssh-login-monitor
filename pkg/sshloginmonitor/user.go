package sshloginmonitor

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/crypto/ssh"
)

type User struct {
	Username    string
	Fingerprint string
}

func UpdateKeysDB(keysFile string, db *bolt.DB, bucket string, follow bool) error {
	f, err := os.Open(keysFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			log.Println("authkeys file not found; database wasn't updated")
			return nil
		}
		return err
	}
	defer f.Close()

	users := make([]User, 0)
	err = getAuthKeys(f, &users)
	if err != nil {
		return err
	}
	err = addUsersToDB(users, db, bucket)
	if err != nil {
		return err
	}
	return nil
}

// getAuthKeys reads an ssh authorized keys file and populates a slice of User structs with the usernames and fingerprints.
// Parameters:
//   - reader: an io.Reader containing the ssh authorized keys file
//   - users: a pointer to a slice of User structs to be populated
//
// Returns:
//   - error: an error if there was an issue reading the file or parsing the keys
func getAuthKeys(reader io.Reader, users *[]User) error {
	scanner := bufio.NewScanner(reader)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		// Parse the authorized key and extract the comment and fingerprint
		out, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(scanner.Text()))
		if err != nil {
			return err
		}

		// If the comment is empty, log a warning and skip this key
		if comment == "" {
			log.Printf("empty comment, remove this fingerprint: %s", out)
			continue
		}

		// Calculate the fingerprint and create a new User struct
		fingerprint := strings.Split(ssh.FingerprintSHA256(out), ":")[1]
		user := User{
			Username:    comment,
			Fingerprint: fingerprint,
		}

		// Append the new User to the slice
		*users = append(*users, user)
	}

	return nil
}

// addUsersToDB adds a slice of User structs to the database.
// Parameters:
//   - users: a slice of User structs to be added to the database
//   - db: a database connection
//   - bucket: the name of the bucket to add the users to
//
// Returns:
//   - error: an error if there was an issue adding the users
func addUsersToDB(users []User, db *bolt.DB, bucket string) error {
	if len(users) == 0 {
		return errors.New("empty users slice")
	}
	reader := bufio.NewReader(os.Stdin)

	for _, user := range users {
		err := db.Update(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte(bucket))
			if b == nil {
				return fmt.Errorf("bucket %s not found", bucket)
			}
			u := b.Get([]byte(user.Fingerprint))
			if u != nil {
				if string(u) != user.Username {
					fmt.Printf("Fingerprint exists in the DB for name: %s\n", u)
					fmt.Printf("New name is: %s. Update? [Y/n]: ", user.Username)
					char, _, err := reader.ReadRune()
					if err != nil {
						return err
					}
					switch char {
					case 'y', 'Y':
						return b.Put([]byte(user.Fingerprint), []byte(user.Username))
					default:
						break
					}
				}
			}
			return b.Put([]byte(user.Fingerprint), []byte(user.Username))
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func GetUserByFingerprint(fp string, db *bolt.DB, bucket string) (string, error) {
	var username string
	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		if b == nil {
			return errors.New("bucket not found")
		}
		username = string(b.Get([]byte(fp)))
		return nil
	})
	if err != nil {
		return "", err
	}
	return username, err
}
