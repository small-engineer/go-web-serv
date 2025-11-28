package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/small-engineer/go-web-serv/web/internal/domain"
)

var (
	ErrInvalidCred = errors.New("invalid credentials")
	ErrUserExists  = errors.New("user already exists")
)

type UserRepo interface {
	FindByName(ctx context.Context, name string) (*domain.User, error)
	FindByID(ctx context.Context, id domain.UserID) (*domain.User, error)
	Create(ctx context.Context, u *domain.User) error
}

type SessionID string

type SessionRepo interface {
	Create(ctx context.Context, u *domain.User) (SessionID, error)
	FindUser(ctx context.Context, id SessionID) (*domain.User, bool, error)
	Delete(ctx context.Context, id SessionID) error
}

type Service struct {
	users UserRepo
}

func NewService(u UserRepo) *Service {
	return &Service{
		users: u,
	}
}

func hashPass(pw string) string {
	sum := sha256.Sum256([]byte(pw))
	return hex.EncodeToString(sum[:])
}

func (s *Service) Login(ctx context.Context, name, pass string) (*domain.User, error) {
	u, err := s.users.FindByName(ctx, name)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, ErrInvalidCred
	}
	hp := hashPass(pass)
	if u.PasswordHash != hp {
		return nil, ErrInvalidCred
	}
	return u, nil
}

func (s *Service) Register(ctx context.Context, name, pass string) (*domain.User, error) {
	ex, err := s.users.FindByName(ctx, name)
	if err != nil {
		return nil, err
	}
	if ex != nil {
		return nil, ErrUserExists
	}
	u := &domain.User{
		Name:         name,
		PasswordHash: hashPass(pass),
	}
	if err := s.users.Create(ctx, u); err != nil {
		return nil, err
	}
	return u, nil
}

func (s *Service) GetByID(ctx context.Context, id domain.UserID) (*domain.User, error) {
	return s.users.FindByID(ctx, id)
}
