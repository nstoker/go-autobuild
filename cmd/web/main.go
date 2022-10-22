package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/nstoker/go-autobuild/internal/database"
	"github.com/nstoker/go-autobuild/internal/leveledlog"
	"github.com/nstoker/go-autobuild/internal/server"
	"github.com/nstoker/go-autobuild/internal/smtp"
	"github.com/nstoker/go-autobuild/internal/version"

	"github.com/gorilla/sessions"
)

type config struct {
	addr    string
	baseURL string
	env     string
	auth    struct {
		username       string
		hashedPassword string
	}
	cookie struct {
		secretKey string
	}
	db struct {
		dsn         string
		automigrate bool
	}
	session struct {
		secretKey    string
		oldSecretKey string
	}
	smtp struct {
		host     string
		port     int
		username string
		password string
		from     string
	}
	tls struct {
		certFile string
		keyFile  string
	}
	version bool
}

type application struct {
	config       config
	db           *database.DB
	logger       *leveledlog.Logger
	mailer       *smtp.Mailer
	sessionStore *sessions.CookieStore
}

func main() {
	var cfg config

	flag.StringVar(&cfg.addr, "addr", "localhost:4444", "server address to listen on")
	flag.StringVar(&cfg.baseURL, "base-url", "https://localhost:4444", "base URL for the application")
	flag.StringVar(&cfg.env, "env", "development", "operating environment: development, testing, staging or production")
	flag.StringVar(&cfg.auth.username, "auth-username", "admin", "basic auth username")
	flag.StringVar(&cfg.auth.hashedPassword, "auth-hashed-password", "$2a$10$jRb2qniNcoCyQM23T59RfeEQUbgdAXfR6S0scynmKfJa5Gj3arGJa", "basic auth password hashed with bcrpyt")
	flag.StringVar(&cfg.cookie.secretKey, "cookie-secret-key", "4XGwaJIi31s6IrX0l6U5KrLBHpQrnly2", "secret key for cookie authentication/encryption")
	flag.StringVar(&cfg.db.dsn, "db-dsn", "user:pass@localhost:5432/db", "postgreSQL DSN")
	flag.BoolVar(&cfg.db.automigrate, "db-automigrate", true, "run migrations on startup")
	flag.StringVar(&cfg.session.secretKey, "session-secret-key", "ucxrde2zcguGtjo4PXHMowMacYzcsfYr", "secret key for session cookie authentication")
	flag.StringVar(&cfg.session.oldSecretKey, "session-old-secret-key", "", "previous secret key for session cookie authentication")
	flag.StringVar(&cfg.smtp.host, "smtp-host", "example.smtp.host", "smtp host")
	flag.IntVar(&cfg.smtp.port, "smtp-port", 25, "smtp port")
	flag.StringVar(&cfg.smtp.username, "smtp-username", "example_username", "smtp username")
	flag.StringVar(&cfg.smtp.password, "smtp-password", "pa55word", "smtp password")
	flag.StringVar(&cfg.smtp.from, "smtp-from", "Example Name <no-reply@example.org>", "smtp sender")
	flag.StringVar(&cfg.tls.certFile, "tls-cert-file", "./tls/cert.pem", "tls certificate file")
	flag.StringVar(&cfg.tls.keyFile, "tls-key-file", "./tls/key.pem", "tls key file")
	flag.BoolVar(&cfg.version, "version", false, "display version and exit")

	flag.Parse()

	if cfg.version {
		fmt.Printf("version: %s\n", version.Get())
		return
	}

	logger := leveledlog.NewLogger(os.Stdout, leveledlog.LevelAll, true)

	db, err := database.New(cfg.db.dsn, cfg.db.automigrate)
	if err != nil {
		logger.Fatal(err)
	}
	defer db.Close()

	mailer := smtp.NewMailer(cfg.smtp.host, cfg.smtp.port, cfg.smtp.username, cfg.smtp.password, cfg.smtp.from)

	keyPairs := [][]byte{[]byte(cfg.session.secretKey), nil}
	if cfg.session.oldSecretKey != "" {
		keyPairs = append(keyPairs, []byte(cfg.session.oldSecretKey), nil)
	}

	sessionStore := sessions.NewCookieStore(keyPairs...)
	sessionStore.Options = &sessions.Options{
		HttpOnly: true,
		MaxAge:   86400 * 7,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		Secure:   true,
	}

	app := &application{
		config:       cfg,
		db:           db,
		logger:       logger,
		mailer:       mailer,
		sessionStore: sessionStore,
	}

	logger.Info("starting server on %s (version %s)", cfg.addr, version.Get())

	err = server.Run(cfg.addr, app.routes(), cfg.tls.certFile, cfg.tls.keyFile)
	if err != nil {
		logger.Fatal(err)
	}

	logger.Info("server stopped")
}
