package domain

type UserID string

type User struct {
	ID           UserID
	Name         string
	PasswordHash string
}
