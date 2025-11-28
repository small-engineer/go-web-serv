package httpadapter

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/small-engineer/go-web-serv/web/internal/domain"
	"github.com/small-engineer/go-web-serv/web/internal/usecase/auth"
)

type Server struct {
	auth *auth.Service
	t    *template.Template
	key  []byte
}

type jwtClaims struct {
	Sub  string `json:"sub"`
	Name string `json:"name"`
	jwt.RegisteredClaims
}

type emailClaims struct {
	Email string `json:"email"`
	jwt.RegisteredClaims
}

func loadTmpl() *template.Template {
	t := template.New("")
	t = template.Must(t.ParseFiles(
		"assets/templates/login.html",
		"assets/templates/register.html",
		"assets/templates/register_email.html",
		"assets/templates/home.html",
	))
	return t
}

func NewServer(a *auth.Service) *Server {
	t := loadTmpl()
	s := os.Getenv("JWT_SECRET")
	if s == "" {
		panic("JWT_SECRET is not set")
	}
	return &Server{
		auth: a,
		t:    t,
		key:  []byte(s),
	}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleHome)
	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/logout", s.handleLogout)
	mux.HandleFunc("/register", s.handleRegister)
	mux.HandleFunc("/register/email", s.handleRegisterEmail)
	fs := http.FileServer(http.Dir("assets/static"))
	mux.Handle("/static/", http.StripPrefix("/static/", fs))
	return mux
}

func (s *Server) currentUser(ctx context.Context, r *http.Request) (*domain.User, bool) {
	c, err := r.Cookie("token")
	if err != nil {
		return nil, false
	}
	cl, err := s.parseToken(c.Value)
	if err != nil {
		return nil, false
	}
	u, err := s.auth.GetByID(ctx, domain.UserID(cl.Sub))
	if err != nil || u == nil {
		return nil, false
	}
	return u, true
}

func (s *Server) renderLogin(w http.ResponseWriter, msg string) {
	err := s.t.ExecuteTemplate(w, "login.html", map[string]any{
		"Error": msg,
	})
	if err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
}

func (s *Server) renderRegister(w http.ResponseWriter, msg, email, tok string) {
	err := s.t.ExecuteTemplate(w, "register.html", map[string]any{
		"Error": msg,
		"Email": email,
		"Token": tok,
	})
	if err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
}

func (s *Server) renderRegisterEmail(w http.ResponseWriter, errMsg, infoMsg string) {
	err := s.t.ExecuteTemplate(w, "register_email.html", map[string]any{
		"Error":   errMsg,
		"Message": infoMsg,
	})
	if err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
}

func (s *Server) issueToken(u *domain.User) (string, error) {
	exp := time.Now().Add(24 * time.Hour)

	cl := jwtClaims{
		Sub:  string(u.ID),
		Name: u.Name,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(exp),
			Subject:   string(u.ID),
		},
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, cl)
	v, err := tok.SignedString(s.key)
	if err != nil {
		return "", err
	}
	return v, nil
}

func (s *Server) parseToken(tok string) (*jwtClaims, error) {
	p, err := jwt.ParseWithClaims(tok, &jwtClaims{}, func(t *jwt.Token) (interface{}, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Method.Alg())
		}
		return s.key, nil
	})
	if err != nil {
		return nil, err
	}
	cl, ok := p.Claims.(*jwtClaims)
	if !ok || !p.Valid {
		return nil, errors.New("invalid token")
	}
	return cl, nil
}

func (s *Server) issueRegisterToken(email string) (string, error) {
	exp := time.Now().Add(1 * time.Hour)
	cl := emailClaims{
		Email: email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(exp),
			Subject:   email,
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, cl)
	v, err := tok.SignedString(s.key)
	if err != nil {
		return "", err
	}
	return v, nil
}

func (s *Server) parseRegisterToken(tok string) (*emailClaims, error) {
	p, err := jwt.ParseWithClaims(tok, &emailClaims{}, func(t *jwt.Token) (interface{}, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Method.Alg())
		}
		return s.key, nil
	})
	if err != nil {
		return nil, err
	}
	cl, ok := p.Claims.(*emailClaims)
	if !ok || !p.Valid {
		return nil, errors.New("invalid token")
	}
	return cl, nil
}
