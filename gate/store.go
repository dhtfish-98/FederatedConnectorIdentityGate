package gate

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var (
	ErrDenied         = errors.New("access_denied")
	ErrSubjectChanged = errors.New("signed_subject_changed")
)

type account struct {
	DexSubjectSHA256 string `json:"dex_subject_sha256"`
	EmailSHA256      string `json:"email_sha256"`
}

type session struct {
	Subject string `json:"subject"`
	Expires int64  `json:"expires"`
}

type resource struct {
	Owner   string `json:"owner"`
	Content string `json:"content"`
}

type state struct {
	Schema    int                 `json:"schema"`
	Accounts  map[string]account  `json:"accounts"`
	Sessions  map[string]session  `json:"sessions"`
	Resources map[string]resource `json:"resources"`
}

func freshState() state {
	return state{Schema: 1, Accounts: map[string]account{}, Sessions: map[string]session{}, Resources: map[string]resource{}}
}

func cloneState(s state) state {
	copy := freshState()
	for key, value := range s.Accounts {
		copy.Accounts[key] = value
	}
	for key, value := range s.Sessions {
		copy.Sessions[key] = value
	}
	for key, value := range s.Resources {
		copy.Resources[key] = value
	}
	return copy
}

func digest(value string) string {
	hash := sha256.Sum256([]byte(value))
	return hex.EncodeToString(hash[:])
}

// subjectKey uses explicit lengths so opaque identifiers cannot collide by
// delimiter ambiguity. Email is deliberately absent.
func subjectKey(v VerifiedIdentity) string {
	h := sha256.New()
	_, _ = h.Write([]byte("fcig-subject-v1"))
	for _, field := range []string{v.issuer, v.connectorID, v.userID} {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(field)))
		_, _ = h.Write(length[:])
		_, _ = h.Write([]byte(field))
	}
	return hex.EncodeToString(h.Sum(nil))
}

type Store struct {
	mu   sync.Mutex
	path string
	ttl  time.Duration
	now  func() time.Time
	data state
}

// OpenStore loads a controlled local file. The calling application must place
// the file in its own protected directory; this package does not sandbox paths.
func OpenStore(path string, ttl time.Duration) (*Store, error) {
	if path == "" || ttl <= 0 || ttl > 24*time.Hour {
		return nil, ErrDenied
	}
	s := &Store{path: path, ttl: ttl, now: time.Now, data: freshState()}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil || !info.Mode().IsRegular() {
		return nil, ErrDenied
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > 2*1024*1024 {
		return nil, ErrDenied
	}
	if err := json.Unmarshal(raw, &s.data); err != nil || s.data.Schema != 1 ||
		s.data.Accounts == nil || s.data.Sessions == nil || s.data.Resources == nil {
		return nil, ErrDenied
	}
	return s, nil
}

func (s *Store) persist(next state) error {
	directory := filepath.Dir(s.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(directory, ".fcig-state-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err := json.NewEncoder(file).Encode(next); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), s.path); err != nil {
		return err
	}
	s.data = next
	return nil
}

func newRandom() (string, error) {
	raw := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func (s *Store) activeSession(token string) (session, bool) {
	if token == "" {
		return session{}, false
	}
	entry, ok := s.data.Sessions[digest(token)]
	return entry, ok && entry.Expires > s.now().Unix()
}

// Bind creates or reuses the verified federated subject, revokes a previously
// presented browser session, and issues a fresh opaque application session.
func (s *Store) Bind(v VerifiedIdentity, priorToken string) (string, string, error) {
	if !v.verified || v.issuer == "" || v.dexSubject == "" || v.connectorID == "" || v.userID == "" || v.email == "" {
		return "", "", ErrUnverified
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneState(s.data)
	if priorToken != "" {
		delete(next.Sessions, digest(priorToken))
	}
	key := subjectKey(v)
	value, exists := next.Accounts[key]
	if exists && value.DexSubjectSHA256 != digest(v.dexSubject) {
		return "", "", ErrSubjectChanged
	}
	next.Accounts[key] = account{DexSubjectSHA256: digest(v.dexSubject), EmailSHA256: digest(v.email)}
	token, err := newRandom()
	if err != nil {
		return "", "", err
	}
	next.Sessions[digest(token)] = session{Subject: key, Expires: s.now().Add(s.ttl).Unix()}
	if err := s.persist(next); err != nil {
		return "", "", err
	}
	return token, key, nil
}

func (s *Store) CreateResource(token, content string) (string, error) {
	if len(content) == 0 || len(content) > 1024 {
		return "", ErrDenied
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	owner, ok := s.activeSession(token)
	if !ok {
		return "", ErrDenied
	}
	id, err := newRandom()
	if err != nil {
		return "", err
	}
	next := cloneState(s.data)
	next.Resources[id] = resource{Owner: owner.Subject, Content: content}
	if err := s.persist(next); err != nil {
		return "", err
	}
	return id, nil
}

func (s *Store) ReadResource(token, id string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	owner, ok := s.activeSession(token)
	if !ok {
		return "", ErrDenied
	}
	value, exists := s.data.Resources[id]
	if !exists || value.Owner != owner.Subject {
		return "", ErrDenied
	}
	return value.Content, nil
}
