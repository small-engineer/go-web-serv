package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"

	"github.com/small-engineer/go-web-serv/web/internal/domain"
)

var (
	ErrInvalidCred = errors.New("invalid credentials")
	ErrUserExists  = errors.New("user already exists")
	ErrEmailExists = errors.New("email already exists")
)

type UserRepo interface {
	FindByName(ctx context.Context, name string) (*domain.User, error)
	FindByEmail(ctx context.Context, email string) (*domain.User, error)
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

func hashPass(pw string) (string, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}

	t := uint32(1)
	m := uint32(64 * 1024)
	p := uint8(4)
	k := uint32(32)

	h := argon2.IDKey([]byte(pw), salt, t, m, p, k)

	sEnc := base64.RawStdEncoding.EncodeToString(salt)
	hEnc := base64.RawStdEncoding.EncodeToString(h)

	v := fmt.Sprintf("argon2id$%d$%d$%d$%d$%s$%s", t, m, p, k, sEnc, hEnc)

	return v, nil
}

func verifyPass(pw, enc string) (bool, error) {
	parts := strings.Split(enc, "$")
	if len(parts) != 7 {
		return false, errors.New("invalid hash format")
	}
	if parts[0] != "argon2id" {
		return false, errors.New("unsupported hash algorithm")
	}

	var t uint32
	var m uint32
	var p uint8
	var k uint32

	_, err := fmt.Sscanf(parts[1], "%d", &t)
	if err != nil {
		return false, err
	}
	_, err = fmt.Sscanf(parts[2], "%d", &m)
	if err != nil {
		return false, err
	}
	_, err = fmt.Sscanf(parts[3], "%d", &p)
	if err != nil {
		return false, err
	}
	_, err = fmt.Sscanf(parts[4], "%d", &k)
	if err != nil {
		return false, err
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, err
	}
	have, err := base64.RawStdEncoding.DecodeString(parts[6])
	if err != nil {
		return false, err
	}

	want := argon2.IDKey([]byte(pw), salt, t, m, p, k)

	if len(want) != len(have) {
		return false, nil
	}

	ok := subtle.ConstantTimeCompare(want, have) == 1
	return ok, nil
}

func (s *Service) Login(ctx context.Context, login, pass string) (*domain.User, error) {
	u, err := s.users.FindByName(ctx, login)
	if err != nil {
		return nil, err
	}
	if u == nil {
		u, err = s.users.FindByEmail(ctx, login)
		if err != nil {
			return nil, err
		}
	}
	if u == nil {
		return nil, ErrInvalidCred
	}
	ok, err := verifyPass(pass, u.PasswordHash)
	if err != nil || !ok {
		return nil, ErrInvalidCred
	}
	return u, nil
}

func (s *Service) Register(ctx context.Context, name, pass, email string) (*domain.User, error) {
	ex, err := s.users.FindByName(ctx, name)
	if err != nil {
		return nil, err
	}
	if ex != nil {
		return nil, ErrUserExists
	}

	ex, err = s.users.FindByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	if ex != nil {
		return nil, ErrEmailExists
	}

	h, err := hashPass(pass)
	if err != nil {
		return nil, err
	}

	u := &domain.User{
		Name:         name,
		Email:        email,
		PasswordHash: h,
	}
	if err := s.users.Create(ctx, u); err != nil {
		return nil, err
	}
	return u, nil
}

func (s *Service) GetByID(ctx context.Context, id domain.UserID) (*domain.User, error) {
	return s.users.FindByID(ctx, id)
}
