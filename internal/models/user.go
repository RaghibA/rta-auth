package models

import "time"

type User struct {
	UserID    string
	Username  string
	Password  []byte
	Email     string
	CreatedAt time.Time
}
