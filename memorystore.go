// Package memorystore implements gorilla session store interface.
// It uses the memory for its backend.
package memorystore

import (
	"encoding/base32"
	"net/http"
	"strings"
	"sync"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
)

// MemoryStore stores sessions in memory.
type MemoryStore struct {
	Codecs  []securecookie.Codec
	Options *sessions.Options
	sync.Mutex
	data map[string]string
}

// NewMemoryStore returns a new memory store.
func NewMemoryStore(keyPairs ...[]byte) *MemoryStore {
	ms := &MemoryStore{
		Codecs: securecookie.CodecsFromPairs(keyPairs...),
		Options: &sessions.Options{
			Path:   "/",
			MaxAge: 86400 * 30,
		},
		data: make(map[string]string),
	}
	ms.MaxAge(ms.Options.MaxAge)
	return ms
}

// MaxLength restricts the maximum length of new sessions to l.
// If l is 0 there is no limit to the size of a session, use with caution.
// The default for a new FilesystemStore is 4096.
func (m *MemoryStore) MaxLength(l int) {
	for _, c := range m.Codecs {
		if codec, ok := c.(*securecookie.SecureCookie); ok {
			codec.MaxLength(l)
		}
	}
}

// MaxAge sets the maximum age for the store and the underlying cookie
// implementation. Individual sessions can be deleted by setting Options.MaxAge
// = -1 for that session.
func (m *MemoryStore) MaxAge(age int) {
	m.Options.MaxAge = age
	// set the maxAge for each securecookie instance
	for _, codec := range m.Codecs {
		if sc, ok := codec.(*securecookie.SecureCookie); ok {
			sc.MaxAge(age)
		}
	}
}

// Get returns a session for the given name after adding it to the registry.
func (m *MemoryStore) Get(r *http.Request, name string) (*sessions.Session, error) {
	return sessions.GetRegistry(r).Get(m, name)
}

// New returns a session for the given name without adding it to the registry.
func (m *MemoryStore) New(r *http.Request, name string) (*sessions.Session, error) {
	session := sessions.NewSession(m, name)
	opts := *m.Options
	session.Options = &opts
	session.IsNew = true
	var err error
	if c, errCookie := r.Cookie(name); errCookie == nil {
		err = securecookie.DecodeMulti(name, c.Value, &session.ID, m.Codecs...)
		if err == nil {
			err = m.load(session)
			if err == nil {
				session.IsNew = false
			}
		}
	}
	return session, err
}

// Save adds a single session to the response.
func (m *MemoryStore) Save(r *http.Request, w http.ResponseWriter, session *sessions.Session) error {
	if session.ID == "" {
		session.ID = strings.TrimRight(
			base32.StdEncoding.EncodeToString(securecookie.GenerateRandomKey(32)),
			"=",
		)
	}
	if err := m.save(session); err != nil {
		return err
	}
	encoded, err := securecookie.EncodeMulti(session.Name(), session.ID, m.Codecs...)
	if err != nil {
		return err
	}
	http.SetCookie(w, sessions.NewCookie(session.Name(), encoded, session.Options))
	return nil
}

// save writes encoded session.Values to its internal map.
func (m *MemoryStore) save(session *sessions.Session) error {
	encoded, err := securecookie.EncodeMulti(session.Name(), session.Values, m.Codecs...)
	if err != nil {
		return err
	}
	m.Lock()
	defer m.Unlock()
	m.data[session.ID] = encoded
	return nil
}

// load reads from its internal map and decodes its content into session.Values.
func (m *MemoryStore) load(session *sessions.Session) error {
	m.Lock()
	defer m.Unlock()
	if data, ok := m.data[session.ID]; ok {
		if err := securecookie.DecodeMulti(
			session.Name(),
			data,
			&session.Values,
			m.Codecs...,
		); err != nil {
			return err
		}
	}
	return nil
}

// GetAll returns all sessions.
func (m *MemoryStore) GetAll() map[string]string {
	m.Lock()
	defer m.Unlock()
	return m.data
}

// Clear removes all sessions from storage.
func (m *MemoryStore) Clear() {
	m.Lock()
	defer m.Unlock()
	m.data = make(map[string]string)
}
