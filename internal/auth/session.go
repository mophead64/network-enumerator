// Package auth provides basic session-cookie authentication. Sessions live
// only in process memory — consistent with the rest of the tool, nothing
// here needs to survive a restart.
package auth

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// CookieName is the session cookie set on login and checked on every
// authenticated request.
const CookieName = "ne_session"

// TTL is how long a session stays valid after its last use.
const TTL = 24 * time.Hour

type SessionStore struct {
	mu       sync.Mutex
	sessions map[string]time.Time
}

func NewSessionStore() *SessionStore {
	return &SessionStore{sessions: make(map[string]time.Time)}
}

// Create mints a new session token.
func (s *SessionStore) Create() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b)
	s.mu.Lock()
	s.sessions[token] = time.Now().Add(TTL)
	s.mu.Unlock()
	return token, nil
}

// Valid reports whether token is a live session, sliding its expiry forward
// on success.
func (s *SessionStore) Valid(token string) bool {
	if token == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.sessions[token]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(s.sessions, token)
		return false
	}
	s.sessions[token] = time.Now().Add(TTL)
	return true
}

// Count returns the number of currently live sessions — how many browser
// tabs/devices are signed in right now, shown as the "active users" count in
// the UI. Since this app has a single admin account, that's really a count
// of concurrent sessions rather than distinct users, but with one account
// the two coincide closely enough to be the useful number to show. Also
// opportunistically drops expired entries it comes across, the same
// lazy-cleanup Valid() already does on every auth check.
func (s *SessionStore) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	n := 0
	for token, exp := range s.sessions {
		if now.After(exp) {
			delete(s.sessions, token)
			continue
		}
		n++
	}
	return n
}

// Revoke invalidates a session token, e.g. on logout.
func (s *SessionStore) Revoke(token string) {
	s.mu.Lock()
	delete(s.sessions, token)
	s.mu.Unlock()
}

// RevokeAll invalidates every outstanding session, e.g. after a password
// change so old sessions can't keep using the previous credentials.
func (s *SessionStore) RevokeAll() {
	s.mu.Lock()
	s.sessions = make(map[string]time.Time)
	s.mu.Unlock()
}
