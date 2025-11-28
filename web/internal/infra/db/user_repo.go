package db

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"

	"github.com/small-engineer/go-web-serv/web/internal/domain"
)

type UserRepo struct {
	db *sql.DB
}

func NewUserRepo(db *sql.DB) *UserRepo {
	return &UserRepo{
		db: db,
	}
}

func newID() (domain.UserID, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return domain.UserID(hex.EncodeToString(b)), nil
}

func (r *UserRepo) FindByName(ctx context.Context, name string) (*domain.User, error) {
	row := r.db.QueryRowContext(ctx, "SELECT id, name, email, password_hash FROM users WHERE name = ?", name)
	var u domain.User
	err := row.Scan(&u.ID, &u.Name, &u.Email, &u.PasswordHash)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (r *UserRepo) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	row := r.db.QueryRowContext(ctx, "SELECT id, name, email, password_hash FROM users WHERE email = ?", email)
	var u domain.User
	err := row.Scan(&u.ID, &u.Name, &u.Email, &u.PasswordHash)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (r *UserRepo) FindByID(ctx context.Context, id domain.UserID) (*domain.User, error) {
	row := r.db.QueryRowContext(ctx, "SELECT id, name, email, password_hash FROM users WHERE id = ?", id)
	var u domain.User
	err := row.Scan(&u.ID, &u.Name, &u.Email, &u.PasswordHash)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (r *UserRepo) Create(ctx context.Context, u *domain.User) error {
	if u.ID == "" {
		id, err := newID()
		if err != nil {
			return err
		}
		u.ID = id
	}
	_, err := r.db.ExecContext(ctx, "INSERT INTO users (id, name, email, password_hash) VALUES (?, ?, ?, ?)", u.ID, u.Name, u.Email, u.PasswordHash)
	return err
}
