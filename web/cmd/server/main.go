package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/small-engineer/go-web-serv/web/internal/adapter/httpadapter"
	infra "github.com/small-engineer/go-web-serv/web/internal/infra/db"
	"github.com/small-engineer/go-web-serv/web/internal/usecase/auth"

	_ "github.com/go-sql-driver/mysql"
)

func getenv(k, def string) string {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	return v
}

func newDB() (*sql.DB, error) {
	host := getenv("DB_HOST", "127.0.0.1")
	port := getenv("DB_PORT", "3306")
	user := getenv("DB_USER", "app")
	pass := getenv("DB_PASSWORD", "apppass")
	name := getenv("DB_NAME", "web")

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
