package routes

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/RaghibA/telemetrix-authn/internal/jwt"
	"github.com/RaghibA/telemetrix-authn/internal/models"
	"github.com/RaghibA/telemetrix-authn/internal/store"
	"github.com/go-playground/validator"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"
)

type Handler struct {
	store  store.UserStore
	logger *log.Logger
}

func NewUserHandler(store store.UserStore, logger *log.Logger) *Handler {
	return &Handler{store: store, logger: logger}
}

func (h *Handler) UserRoutes(router *mux.Router) {
	router.HandleFunc("/healthz", h.healthz).Methods(http.MethodGet)
	router.HandleFunc("/register", h.createUser).Methods(http.MethodPost)
	router.HandleFunc("/login", h.loginUser).Methods(http.MethodPost)
	router.HandleFunc("/access-token", jwt.AuthWithCookie(h.generateToken)).Methods(http.MethodPost)
	router.HandleFunc("/logout", jwt.AuthWithCookie(h.logoutUser)).Methods(http.MethodPost)
}

func (h *Handler) healthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Health OK",
	})
}

type CreateUserRequestBody struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
}

func (h *Handler) createUser(w http.ResponseWriter, r *http.Request) {
	var user CreateUserRequestBody
	decoder := json.NewDecoder(r.Body)
	validator := validator.New()

	if err := decoder.Decode(&user); err != nil {
		h.logger.Println(err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := validator.Var(user.Email, "required,email"); err != nil {
		h.logger.Println(err)
		http.Error(w, "Invalid email", http.StatusBadRequest)
		return
	}

	if err := validator.Var(user.Password, "required,min=8"); err != nil {
		h.logger.Println(err)
		http.Error(w, "Password must be at least 8 characters", http.StatusBadRequest)
		return
	}

	if err := validator.Var(user.Username, "required,min=6"); err != nil {
		h.logger.Println(err)
		http.Error(w, "Username must be at least 6 characters", http.StatusBadRequest)
		return
	}

	ctx := context.Background()
	_, err := h.store.GetUserByEmail(ctx, user.Email)
	if err != nil && err != pgx.ErrNoRows {
		h.logger.Println(err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if err == nil {
		h.logger.Println(err)
		http.Error(w, "An account with this email already exists", http.StatusConflict)
		return
	}

	_, err = h.store.GetUserByUsername(ctx, user.Username)
	if err != nil && err != pgx.ErrNoRows {
		h.logger.Println(err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if err == nil {
		h.logger.Println(err)
		http.Error(w, "An account with this username already exists", http.StatusConflict)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), 14)
	if err != nil {
		h.logger.Println(err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	newUser := models.User{
		UserID:    uuid.New().String(),
		Username:  user.Username,
		Password:  hashedPassword,
		Email:     user.Email,
		CreatedAt: time.Now(),
	}

	dbctx := context.Background()

	if err := h.store.AddUser(dbctx, newUser); err != nil {
		h.logger.Println(err)
		http.Error(w, "Failed to create account", http.StatusInternalServerError)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Account created",
	})
}

type LoginRequestBody struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (h *Handler) loginUser(w http.ResponseWriter, r *http.Request) {
	var loginBody LoginRequestBody
	decoder := json.NewDecoder(r.Body)

	if err := decoder.Decode(&loginBody); err != nil {
		h.logger.Println(err)
		http.Error(w, "Invalid Request Body", http.StatusBadRequest)
		return
	}

	if loginBody.Username == "" || loginBody.Password == "" {
		http.Error(w, "Username and Password are required", http.StatusBadRequest)
		return
	}

	dbctx := context.Background()
	user, err := h.store.GetUserByUsername(dbctx, loginBody.Username)
	if err == pgx.ErrNoRows {
		h.logger.Println(err)
		http.Error(w, "User not found", http.StatusBadRequest)
		return
	}
	if err != nil {
		h.logger.Println(err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	err = bcrypt.CompareHashAndPassword(user.Password, []byte(loginBody.Password))
	if err != nil {
		h.logger.Println(err)
		http.Error(w, "Login Failed", http.StatusUnauthorized)
		return
	}

	token, err := jwt.GenerateCookie(user.UserID, time.Now().Add(time.Hour*24*7))
	if err != nil {
		h.logger.Println(err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	cookie := &http.Cookie{
		Name:     "refresh_token",
		Value:    token,
		Path:     "/",
		Expires:  time.Now().Add(time.Hour * 24 * 7),
		HttpOnly: true,
		Secure:   false,
	}

	http.SetCookie(w, cookie)

	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "login successful",
	})
}

func (h *Handler) generateToken(w http.ResponseWriter, r *http.Request) {
	userId, ok := r.Context().Value(jwt.UserKey).(string)
	if !ok {
		h.logger.Println("No userId in request context")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	jwt, err := jwt.GenerateAccessToken(userId, time.Now().Add(time.Hour*1))
	if err != nil {
		h.logger.Println(err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"accessToken": jwt,
		"expiresAt":   time.Now().Add(time.Minute * 30).Unix(),
	})
}

func (h *Handler) logoutUser(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Path:     "/",
	})

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Logged out successfully",
	})
}
