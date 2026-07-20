module cli-login-system

go 1.22.2

require (
	github.com/chzyer/readline v1.5.1
	github.com/jackc/pgx/v5 v5.7.1
	github.com/pquerna/otp v1.5.0
	golang.org/x/crypto v0.27.0
)

require (
	github.com/boombuler/barcode v1.0.1-0.20190219062509-6c824513bacc // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	golang.org/x/sync v0.8.0 // indirect
	golang.org/x/sys v0.21.0 // indirect
	golang.org/x/text v0.18.0 // indirect
)

replace golang.org/x/sys => github.com/golang/sys v0.18.0

replace golang.org/x/crypto => github.com/golang/crypto v0.24.0

replace gopkg.in/yaml.v3 => github.com/go-yaml/yaml/v3 v3.0.1

replace golang.org/x/text => github.com/golang/text v0.18.0

replace gopkg.in/check.v1 => github.com/go-check/check v0.0.0-20200902074654-038fdea0a05b

replace golang.org/x/sync => github.com/golang/sync v0.8.0
