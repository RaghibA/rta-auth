package store

import (
	"context"
	"log"

	"github.com/RaghibA/telemetrix-authn/internal/models"
	"github.com/jackc/pgx/v5"
)

type UserStore interface {
	GetUserById(ctx context.Context, userId string) (*models.User, error)
	GetUserByUsername(ctx context.Context, username string) (*models.User, error)
	GetUserByEmail(ctx context.Context, email string) (*models.User, error)
	AddUser(ctx context.Context, user models.User) error
	DeleteUser(ctx context.Context, userId string) error
}

type store struct {
	db     *pgx.Conn
	logger *log.Logger
}

func NewUserStore(db *pgx.Conn, logger *log.Logger) *store {
	return &store{
		db:     db,
		logger: logger,
	}
}

func (s *store) GetUserById(ctx context.Context, userId string) (*models.User, error) {
	var user models.User

	queryString := `
			SELECT user_id, username, password, email, created_at FROM users WHERE user_id=$1		
	`

	err := s.db.QueryRow(ctx, queryString, userId).Scan(
		&user.UserID,
		&user.Username,
		&user.Password,
		&user.Email,
		&user.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

func (s *store) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	var user models.User

	queryString := `
		SELECT user_id, username, password, email, created_at FROM users WHERE username=$1
	`
	err := s.db.QueryRow(ctx, queryString, username).Scan(
		&user.UserID,
		&user.Username,
		&user.Password,
		&user.Email,
		&user.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

func (s *store) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	var user models.User

	queryString := `
		SELECT user_id, username, password, email, created_at FROM users WHERE email=$1
	`
	err := s.db.QueryRow(ctx, queryString, email).Scan(
		&user.UserID,
		&user.Username,
		&user.Password,
		&user.Email,
		&user.CreatedAt,
	)
	if err != nil {
		return &models.User{}, err
	}

	return &user, nil
}

func (s *store) AddUser(ctx context.Context, user models.User) error {
	queryString := `
		INSERT INTO users (user_id, username, password, email)
		VALUES ($1, $2, $3, $4)
	`

	_, err := s.db.Exec(ctx, queryString, user.UserID, user.Username, user.Password, user.Email)
	return err
}

func (s *store) DeleteUser(ctx context.Context, userId string) error {
	queryString := `
		DELETE FROM users WHERE user_id=$1
	`

	_, err := s.db.Exec(ctx, queryString, userId)
	return err
}
