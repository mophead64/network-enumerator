package store

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
)

const (
	DefaultUsername = "admin"
	DefaultPassword = "password1234"
)

func hashPassword(password, saltHex string) string {
	salt, _ := hex.DecodeString(saltHex)
	sum := sha256.Sum256(append(salt, []byte(password)...))
	return hex.EncodeToString(sum[:])
}

func newSalt() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ensureDefaultAuth seeds the single admin credential row on first run, using
// initialPassword in place of DefaultPassword when it's non-empty.
func (s *Store) ensureDefaultAuth(initialPassword string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM auth`).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	password := DefaultPassword
	if initialPassword != "" {
		password = initialPassword
	}
	salt, err := newSalt()
	if err != nil {
		return err
	}
	hash := hashPassword(password, salt)
	_, err = s.db.Exec(`INSERT INTO auth (id, username, password_hash, password_salt) VALUES (1, ?, ?, ?)`,
		DefaultUsername, hash, salt)
	return err
}

// VerifyCredentials reports whether username/password match the current
// stored credentials.
func (s *Store) VerifyCredentials(username, password string) bool {
	s.mu.Lock()
	var dbUser, hash, salt string
	err := s.db.QueryRow(`SELECT username, password_hash, password_salt FROM auth WHERE id = 1`).Scan(&dbUser, &hash, &salt)
	s.mu.Unlock()
	if err != nil {
		return false
	}
	if subtle.ConstantTimeCompare([]byte(username), []byte(dbUser)) != 1 {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(hashPassword(password, salt)), []byte(hash)) == 1
}

// UsingDefaultCredentials reports whether the account still has the
// out-of-the-box admin/password1234 credentials, so the login screen can
// show a hint that disappears once they've been changed.
func (s *Store) UsingDefaultCredentials() bool {
	return s.VerifyCredentials(DefaultUsername, DefaultPassword)
}

// CurrentUsername returns the active admin username.
func (s *Store) CurrentUsername() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var u string
	err := s.db.QueryRow(`SELECT username FROM auth WHERE id = 1`).Scan(&u)
	return u, err
}

// UpdateCredentials changes the admin username/password.
func (s *Store) UpdateCredentials(username, password string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	salt, err := newSalt()
	if err != nil {
		return err
	}
	hash := hashPassword(password, salt)
	_, err = s.db.Exec(`UPDATE auth SET username = ?, password_hash = ?, password_salt = ? WHERE id = 1`, username, hash, salt)
	return err
}
