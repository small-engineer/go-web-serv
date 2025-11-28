package httpadapter

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"os"
	"strings"
	"time"

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
	Exp  int64  `json:"exp"`
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
		s = "dev-secret-change-me"
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
	if cl.Exp <= time.Now().Unix() {
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
	h := map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	}
	hb, err := json.Marshal(h)
	if err != nil {
		return "", err
	}
	exp := time.Now().Add(24 * time.Hour).Unix()
	cl := jwtClaims{
		Sub:  string(u.ID),
		Name: u.Name,
		Exp:  exp,
	}
	pb, err := json.Marshal(cl)
	if err != nil {
		return "", err
	}
	hEnc := base64.RawURLEncoding.EncodeToString(hb)
	pEnc := base64.RawURLEncoding.EncodeToString(pb)
	head := hEnc + "." + pEnc
	mac := hmac.New(sha256.New, s.key)
	_, err = mac.Write([]byte(head))
	if err != nil {
		return "", err
	}
	sig := mac.Sum(nil)
	sEnc := base64.RawURLEncoding.EncodeToString(sig)
	return head + "." + sEnc, nil
}

func (s *Server) parseToken(tok string) (*jwtClaims, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token")
	}
	head := parts[0] + "." + parts[1]
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("invalid token")
	}
	mac := hmac.New(sha256.New, s.key)
	_, err = mac.Write([]byte(head))
	if err != nil {
		return nil, err
	}
	expSig := mac.Sum(nil)
	if !hmac.Equal(sig, expSig) {
		return nil, errors.New("invalid token")
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("invalid token")
	}
	var cl jwtClaims
	err = json.Unmarshal(pb, &cl)
	if err != nil {
		return nil, errors.New("invalid token")
	}
	return &cl, nil
}
