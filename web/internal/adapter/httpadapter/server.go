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

func loadTmpl() *template.Template {
	t := template.New("")
	t = template.Must(t.ParseFiles(
		"assets/templates/login.html",
		"assets/templates/register.html",
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
	fs := http.FileServer(http.Dir("assets/static"))
	mux.Handle("/static/", http.StripPrefix("/static/", fs))
	return mux
}

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	u, ok := s.currentUser(ctx, r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	err := s.t.ExecuteTemplate(w, "home.html", map[string]any{
		"Username": u.Name,
	})
	if err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		s.renderLogin(w, "")
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	name := r.Form.Get("username")
	pass := r.Form.Get("password")

	ctx := r.Context()
	u, err := s.auth.Login(ctx, name, pass)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCred) {
			s.renderLogin(w, "ユーザー名またはパスワードが違います")
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	tok, err := s.issueToken(u)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	c := &http.Cookie{
		Name:     "token",
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, c)

	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		s.renderRegister(w, "")
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	name := r.Form.Get("username")
	pass := r.Form.Get("password")

	ctx := r.Context()
	u, err := s.auth.Register(ctx, name, pass)
	if err != nil {
		if errors.Is(err, auth.ErrUserExists) {
			s.renderRegister(w, "そのユーザー名は既に使われています")
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	tok, err := s.issueToken(u)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	c := &http.Cookie{
		Name:     "token",
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, c)

	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("token")
	if err == nil {
		c.MaxAge = -1
		http.SetCookie(w, c)
	}
	http.Redirect(w, r, "/login", http.StatusFound)
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

func (s *Server) renderRegister(w http.ResponseWriter, msg string) {
	err := s.t.ExecuteTemplate(w, "register.html", map[string]any{
		"Error": msg,
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
