module github.com/nstoker/go-autobuild

go 1.23.0

replace (
	github.com/coreos/bbolt => go.etcd.io/bbolt v1.3.5
	go.uber.org/atomic => github.com/uber-go/atomic v1.5.0
)

require (
	github.com/alexedwards/flow v0.0.0-20220421161004-151985479ec9
	github.com/fatih/color v1.7.0
	github.com/go-mail/mail/v2 v2.3.0
	github.com/go-playground/form/v4 v4.2.0
	github.com/golang-migrate/migrate/v4 v4.15.2
	github.com/gorilla/sessions v1.2.1
	github.com/jmoiron/sqlx v1.3.5
	github.com/justinas/nosurf v1.2.0
	github.com/lib/pq v1.10.0
	golang.org/x/crypto v0.35.0
	golang.org/x/exp v0.0.0-20220518171630-0b5c67f07fdf
	golang.org/x/text v0.22.0
)

require (
	github.com/gorilla/securecookie v1.1.1 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/mattn/go-colorable v0.1.6 // indirect
	github.com/mattn/go-isatty v0.0.12 // indirect
	go.uber.org/atomic v1.7.0 // indirect
	golang.org/x/lint v0.0.0-20210508222113-6edffad5e616 // indirect
	golang.org/x/sys v0.30.0 // indirect
	golang.org/x/tools v0.21.1-0.20240508182429-e35e4ccd0d2d // indirect
	gopkg.in/alexcesaro/quotedprintable.v3 v3.0.0-20150716171945-2caba252f4dc // indirect
	gopkg.in/mail.v2 v2.3.1 // indirect
)
