package server

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/RaghibA/telemetrix-authn/internal/config"
	"github.com/RaghibA/telemetrix-authn/internal/monitoring"
	"github.com/RaghibA/telemetrix-authn/internal/routes"
	"github.com/RaghibA/telemetrix-authn/internal/store"
	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
)

type AuthServer struct {
	Addr   string
	Db     *pgx.Conn
	Logger *log.Logger
}

func NewAuthServer(config *config.AuthConfig, db *pgx.Conn) *AuthServer {
	addr := fmt.Sprintf("%s:%s", config.HOST, config.PORT)
	logger := log.New(os.Stdout, "AUTH_SERVER: ", log.LstdFlags)

	return &AuthServer{
		Addr:   addr,
		Db:     db,
		Logger: logger,
	}
}

func (s *AuthServer) Run() error {
	metrics := monitoring.NewMetrics()

	router := mux.NewRouter()
	subRouter := router.PathPrefix("/api/v1/auth").Subrouter()
	subRouter.Use(metrics.MetricMonitoring) // Apply middleware to only this subrouter

	userStore := store.NewUserStore(s.Db, s.Logger)
	userHandler := routes.NewUserHandler(userStore, s.Logger)
	userHandler.UserRoutes(subRouter)

	router.Handle("/metrics", monitoring.PrometheusHandler()) // Expose metrics at /metrics

	log.Printf("Auth server running on %v", s.Addr)
	return http.ListenAndServe(s.Addr, router)
}
