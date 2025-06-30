package app

import (
	"log"

	"github.com/RaghibA/telemetrix-authn/internal/config"
	"github.com/RaghibA/telemetrix-authn/internal/db"
	"github.com/RaghibA/telemetrix-authn/internal/server"
)

func Run() {
	log.Println("Starting telemetrix auth service")

	dbConfig, err := config.GetDBConfig()
	if err != nil {
		log.Fatal(err)
	}
	db, err := db.NewDB(dbConfig)
	if err != nil {
		log.Fatal(err)
	}

	authConfig, err := config.GetAuthConfig()
	if err != nil {
		log.Fatal(err)
	}

	s := server.NewAuthServer(authConfig, db)
	if err := s.Run(); err != nil {
		log.Fatal(err)
	}
}
