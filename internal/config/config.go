package config

import (
	"fmt"

	"github.com/RaghibA/telemetrix-authn/internal/utils"
)

type AuthConfig struct {
	HOST      string
	PORT      string
	JWTSECRET string
}

type DBConfig struct {
	PostgresUser string
	PostgresPass string
	PostgresName string
	PostgresPort string
}

func GetAuthConfig() (*AuthConfig, error) {
	host, err := utils.GetEnv("HOST", "")
	if err != nil {
		return nil, err
	}

	port, err := utils.GetEnv("PORT", "")
	if err != nil {
		return nil, err
	}

	jwtSecret, err := utils.GetEnv("JWT_SECRET", "")
	if err != nil {
		return nil, err
	}

	return &AuthConfig{
		HOST:      host,
		PORT:      port,
		JWTSECRET: jwtSecret,
	}, nil
}

func GetDBString(config *DBConfig) string {
	return fmt.Sprintf("postgres://%v:%v@%v:%v/%v?sslmode=disable",
		config.PostgresUser,
		config.PostgresPass,
		"db",
		config.PostgresPort,
		config.PostgresName,
	)
}

func GetDBConfig() (*DBConfig, error) {
	user, err := utils.GetEnv("DB_USER", "")
	if err != nil {
		return nil, err
	}

	pass, err := utils.GetEnv("DB_PASS", "")
	if err != nil {
		return nil, err
	}

	name, err := utils.GetEnv("DB_NAME", "")
	if err != nil {
		return nil, err
	}

	port, err := utils.GetEnv("DB_PORT", "")
	if err != nil {
		return nil, err
	}

	return &DBConfig{
		PostgresUser: user,
		PostgresPass: pass,
		PostgresName: name,
		PostgresPort: port,
	}, nil
}
