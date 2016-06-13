package auth

import (
	"errors"
	"golang.org/x/crypto/scrypt"
	"io/ioutil"
	"os"
	"fmt"
)


func Login(username string, passwd string) (bool, error) {
	userPass, err := loadHashedPwd(username)

	fmt.Printf("Login!")

	if err != nil {
		return false, errors.New("Invalid credentials")
	}

	fmt.Printf("Login: %s / %s", username, passwd)

	if userPass == hashPassword(passwd, username) {
		createToken(username)
		return true, nil
	}

	return false, errors.New("Invalid credentials")
}

func Logout(username string) {
	os.Remove("tokens/" + username)
}

func CreateAccount(username string, password string) {
	hash := hashPassword(password, username)
	savePass(hash, username)
}

// Authenticated checks for the existence of a token for this username.
func Authenticated(username string) bool {
	filename := "tokens/" + username
  _, err := ioutil.ReadFile(filename)
 	return err == nil
}


// hashPassword takes in a password and a salt, scrypts and returns the key.
func hashPassword(psw string, salt string) string {
	dk, _ := scrypt.Key([]byte(psw), []byte(salt), 16384, 8, 1, 32)
	return string(dk)
}

// createToken creates a token for a given fileName.
func createToken(fileName string) {
	path := "tokens/" + fileName
	ioutil.WriteFile(path, []byte("A TOKEN EXISTS"), 0644)
}

// Loads the pre-salted and hashed password from a handy text file
func loadHashedPwd(title string) (string, error) {
  filename := "pw/" + title
  fmt.Printf("load pass! %s", title)
  body, err := ioutil.ReadFile(filename)
  if err != nil {
  	return "", err
  }
  return string(body), nil
}

func savePass(passhash string, filename string) {
	fmt.Printf("Save pass! %s", passhash)

	path := "pw/" + filename
	ioutil.WriteFile(path, []byte(passhash), 0644)
}