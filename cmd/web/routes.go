package main

import (
	"net/http"

	"github.com/nstoker/go-autobuild/assets"

	"github.com/alexedwards/flow"
)

func (app *application) routes() http.Handler {
	mux := flow.New()
	mux.NotFound = http.HandlerFunc(app.notFound)

	mux.Use(app.recoverPanic)
	mux.Use(app.securityHeaders)
	mux.Use(app.preventCSRF)
	mux.Use(app.authenticate)

	mux.HandleFunc("/", app.home, "GET")

	mux.Group(func(mux *flow.Mux) {
		mux.Use(app.requireBasicAuthentication)

		mux.HandleFunc("/basic-auth-protected", app.protected, "GET")
	})

	mux.Group(func(mux *flow.Mux) {
		mux.Use(app.requireAnonymousUser)

		mux.HandleFunc("/signup", app.signup, "GET", "POST")
		mux.HandleFunc("/login", app.login, "GET", "POST")
		mux.HandleFunc("/forgotten-password", app.forgottenPassword, "GET", "POST")
		mux.HandleFunc("/forgotten-password-confirmation", app.forgottenPasswordConfirmation, "GET")
		mux.HandleFunc("/password-reset/:plaintextToken", app.passwordReset, "GET", "POST")
		mux.HandleFunc("/password-reset-confirmation", app.passwordResetConfirmation, "GET")
	})

	mux.Group(func(mux *flow.Mux) {
		mux.Use(app.requireAuthenticatedUser)

		mux.HandleFunc("/logout", app.logout, "POST")
	})

	fileServer := http.FileServer(http.FS(assets.EmbeddedFiles))
	mux.Handle("/static/...", fileServer, "GET")

	return mux
}
