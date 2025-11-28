package main

import (
	"bufio"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/small-engineer/go-web-serv/web/internal/adapter/httpadapter"
	infra "github.com/small-engineer/go-web-serv/web/internal/infra/db"
	"github.com/small-engineer/go-web-serv/web/internal/usecase/auth"

	_ "github.com/go-sql-driver/mysql"
)

const devEnvFile = ".env.dev"

func loadDevEnv() {
	f, err := os.Open(devEnvFile)
	if err != nil {
		return
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		ln := strings.TrimSpace(sc.Text())
		if ln == "" {
			continue
		}
		if strings.HasPrefix(ln, "#") {
			continue
		}
		if strings.HasPrefix(ln, "export ") {
			ln = strings.TrimSpace(ln[len("export "):])
		}
		i := strings.IndexByte(ln, '=')
		if i <= 0 {
			continue
		}
		k := strings.TrimSpace(ln[:i])
		v := strings.TrimSpace(ln[i+1:])
		if k == "" {
			continue
		}
		if os.Getenv(k) != "" {
			continue
		}
		os.Setenv(k, v)
	}
}

func getenv(k string) string {
	v := os.Getenv(k)
	if v == "" {
		log.Fatalf("env %s is not set", k)
	}
	return v
}

func newDB() (*sql.DB, error) {
	host := getenv("DB_HOST")
	port := getenv("DB_PORT")
	user := getenv("DB_USER")
	pass := getenv("DB_PASSWORD")
	name := getenv("DB_NAME")

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true&charset=utf8mb4&collation=utf8mb4_unicode_ci", user, pass, host, port, name)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		return nil, err
	}
	return db, nil
}

func main() {
	loadDevEnv()

	db, err := newDB()
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	ur := infra.NewUserRepo(db)
	svc := auth.NewService(ur)
	s := httpadapter.NewServer(svc)

	h := s.Routes()
	addr := ":8080"

	log.Printf("start server on %s", addr)

	if err := http.ListenAndServe(addr, h); err != nil {
		log.Fatal(err)
	}
}
