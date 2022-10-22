package main

import (
	"net/http"

	"github.com/nstoker/go-autobuild/internal/version"

	"github.com/justinas/nosurf"
)

func (app *application) newTemplateData(r *http.Request) map[string]any {
	data := map[string]any{
		"AuthenticatedUser": contextGetAuthenticatedUser(r),
		"CSRFToken":         nosurf.Token(r),
		"Version":           version.Get(),
	}

	return data
}

func (app *application) newEmailData(r *http.Request) map[string]any {
	data := map[string]any{
		"BaseURL": app.config.baseURL,
	}

	return data
}
