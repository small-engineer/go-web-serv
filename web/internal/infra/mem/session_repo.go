package mem

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"

	"github.com/small-engineer/go-web-serv/web/internal/domain"
	"github.com/small-engineer/go-web-serv/web/internal/usecase/auth"
)

type SessionRepo struct {
	mu sync.Mutex
	m  map[auth.SessionID]*domain.User
}

func NewSessionRepo() *SessionRepo {
	return &SessionRepo{
		m: make(map[auth.SessionID]*domain.User),
	}
}

func (r *SessionRepo) Create(ctx context.Context, u *domain.User) (auth.SessionID, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	id := auth.SessionID(hex.EncodeToString(b))

	r.mu.Lock()
	r.m[id] = u
	r.mu.Unlock()

	return id, nil
}

func (r *SessionRepo) FindUser(ctx context.Context, id auth.SessionID) (*domain.User, bool, error) {
	r.mu.Lock()
	u, ok := r.m[id]
	r.mu.Unlock()
	if !ok {
		return nil, false, nil
	}
	return u, true, nil
}

func (r *SessionRepo) Delete(ctx context.Context, id auth.SessionID) error {
	r.mu.Lock()
	delete(r.m, id)
	r.mu.Unlock()
	return nil
}
