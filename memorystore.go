package memorystore

import (
	"encoding/base32"
	"net/http"
	"strings"
	"sync"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
)

type MemoryStore struct {
	Codecs  []securecookie.Codec
	Options *sessions.Options
	sync.Mutex
	data map[string]string
}

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

func (m *MemoryStore) MaxLength(l int) {
	for _, c := range m.Codecs {
		if codec, ok := c.(*securecookie.SecureCookie); ok {
			codec.MaxLength(l)
		}
	}
}

func (m *MemoryStore) MaxAge(age int) {
	m.Options.MaxAge = age
	// set the maxAge for each securecookie instance
	for _, codec := range m.Codecs {
		if sc, ok := codec.(*securecookie.SecureCookie); ok {
			sc.MaxAge(age)
		}
	}
}

func (m *MemoryStore) Get(r *http.Request, name string) (*sessions.Session, error) {
	return sessions.GetRegistry(r).Get(m, name)
}

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
