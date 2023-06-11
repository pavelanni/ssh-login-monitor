package sshloginmonitor

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/fsnotify/fsnotify"
	"github.com/pavelanni/ssh-login-monitor/pkg/config"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/crypto/ssh"
)

type User struct {
	Username    string
	Fingerprint string
}

func UpdateKeysDB(ctx context.Context, keysFiles []string, db *bolt.DB, bucket string, follow bool) error {
	offsets := make(map[string]int64)
	files := make(map[string]*os.File)

	for _, keysFile := range keysFiles {
		f, err := os.Open(keysFile)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				log.Println("authkeys file not found; database wasn't updated")
				return nil
			}
			return err
		}
		defer f.Close()
		log.Println("adding keys from file: ", keysFile)
		users := make([]User, 0)
		files[keysFile] = f
		err = getAuthKeys(f, &users)
		if err != nil {
			return err
		}
		offset, err := f.Seek(0, io.SeekCurrent)
		if err != nil {
			return err
		}
		offsets[keysFile] = offset
		err = addUsersToDB(users, db, bucket)
		if err != nil {
			return err
		}
	}
	if !follow {
		return nil
	}

	// if follow is true, watch the authkeys file for changes and update the database
	//var offset int64
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer watcher.Close()
	for _, keysFile := range keysFiles {
		err = watcher.Add(keysFile)
		if err != nil {
			return err
		}
	}
	log.Println("watcher: ", watcher)
	for {
		select {
		case <-ctx.Done():
			return nil
		case ev := <-watcher.Events:
			if ev.Op&fsnotify.Write == fsnotify.Write {
				log.Println("key was added to file: ", ev.Name)
				f := files[ev.Name]
				offset := offsets[ev.Name]
				_, err := f.Seek(offset, io.SeekStart)
				if err != nil {
					return err
				}
				scanner := bufio.NewScanner(f)
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
					err = addOneUserToDB(user, db, bucket)
					if err != nil {
						return err
					}
				}
			}
		case err := <-watcher.Errors:
			return err
		}
	}
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

	for _, user := range users {
		err := addOneUserToDB(user, db, bucket)
		if err != nil {
			return err
		}
	}
	return nil
}

func addOneUserToDB(user User, db *bolt.DB, bucket string) error {
	err := db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		if b == nil {
			return fmt.Errorf("bucket %s not found", bucket)
		}
		u := b.Get([]byte(user.Fingerprint))
		if u != nil { // If the fingerprint is already in the database
			if !config.K.Bool("updatekeys") { // skip if --updatekeys is set to false
				return nil
			}
		}
		log.Printf("adding fingerprint for user %s", user.Username)
		return b.Put([]byte(user.Fingerprint), []byte(user.Username))
	})
	if err != nil {
		return err
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
