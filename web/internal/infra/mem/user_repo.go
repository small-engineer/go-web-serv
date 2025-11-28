package mem

import (
	"context"

	"github.com/small-engineer/go-web-serv/web/internal/domain"
)

type UserRepo struct {
	m map[string]*domain.User
}

func NewUserRepo() *UserRepo {
	m := make(map[string]*domain.User)
	return &UserRepo{
		m: m,
	}
}

func (r *UserRepo) FindByName(ctx context.Context, name string) (*domain.User, error) {
	u, ok := r.m[name]
	if !ok {
		return nil, nil
	}
	return u, nil
}

func (r *UserRepo) FindByID(ctx context.Context, id domain.UserID) (*domain.User, error) {
	for _, u := range r.m {
		if u.ID == id {
			return u, nil
		}
	}
	return nil, nil
}

func (r *UserRepo) Create(ctx context.Context, u *domain.User) error {
	r.m[u.Name] = u
	return nil
}
