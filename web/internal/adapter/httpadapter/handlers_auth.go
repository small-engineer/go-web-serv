package httpadapter

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/small-engineer/go-web-serv/web/internal/usecase/auth"
)

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
	login := r.Form.Get("login")
	pass := r.Form.Get("password")

	ctx := r.Context()
	u, err := s.auth.Login(ctx, login, pass)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCred) {
			s.renderLogin(w, "ユーザー名またはメールアドレス、またはパスワードが違います")
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

func (s *Server) handleRegisterEmail(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		s.renderRegisterEmail(w, "", "")
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
	email := strings.TrimSpace(r.Form.Get("email"))
	if email == "" {
		s.renderRegisterEmail(w, "メールアドレスを入力してください", "")
		return
	}
	if !strings.Contains(email, "@") {
		s.renderRegisterEmail(w, "メールアドレスの形式が不正です", "")
		return
	}

	tok, err := s.issueRegisterToken(email)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	u := fmt.Sprintf("%s://%s/register?token=%s", scheme, r.Host, url.QueryEscape(tok))

	subj := "ユーザー登録のご案内"
	body := fmt.Sprintf("以下のURLを開いてユーザー名の設定とユーザー登録を完了してください。\n\n%s\n\nこのリンクは1時間で期限切れになります。", u)

	err = sendMail(email, subj, body)
	if err != nil {
		http.Error(w, "メール送信に失敗しました", http.StatusInternalServerError)
		return
	}

	s.renderRegisterEmail(w, "", "確認メールを送信しました。メールをご確認ください。")
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		q := r.URL.Query()
		tok := q.Get("token")
		if tok == "" {
			http.Redirect(w, r, "/register/email", http.StatusFound)
			return
		}
		cl, err := s.parseRegisterToken(tok)
		if err != nil {
			s.renderRegisterEmail(w, "確認URLの有効期限が切れています。もう一度メールアドレス入力からやり直してください。", "")
			return
		}
		s.renderRegister(w, "", cl.Email, tok)
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
	tok := r.Form.Get("token")

	if tok == "" {
		http.Redirect(w, r, "/register/email", http.StatusFound)
		return
	}
	cl, err := s.parseRegisterToken(tok)
	if err != nil {
		s.renderRegisterEmail(w, "確認URLの有効期限が切れています。もう一度メールアドレス入力からやり直してください。", "")
		return
	}
	email := cl.Email

	ctx := r.Context()
	u, err := s.auth.Register(ctx, name, pass, email)
	if err != nil {
		if errors.Is(err, auth.ErrUserExists) {
			s.renderRegister(w, "そのユーザー名は既に使われています", email, tok)
			return
		}
		if errors.Is(err, auth.ErrEmailExists) {
			s.renderRegister(w, "そのメールアドレスは既に登録されています", email, tok)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	tok2, err := s.issueToken(u)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	c := &http.Cookie{
		Name:     "token",
		Value:    tok2,
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
